package org.vimal.security.v1.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v1.dto.*;
import org.vimal.security.v1.exception.BadRequestExc;
import org.vimal.security.v1.model.PermissionModel;
import org.vimal.security.v1.model.RoleModel;
import org.vimal.security.v1.model.UserModel;
import org.vimal.security.v1.model.enums.SystemRole;
import org.vimal.security.v1.repo.PermissionModelRepo;
import org.vimal.security.v1.repo.RoleModelRepo;
import org.vimal.security.v1.repo.UserModelRepo;
import org.vimal.security.v1.service.util.CurrentUserUtil;
import org.vimal.security.v1.service.util.InputValidationUtil;
import org.vimal.security.v1.util.jwt.JwtUtil;
import org.vimal.security.v1.util.mapper.RoleMapperUtil;
import org.vimal.security.v1.util.mapper.UserMapperUtil;
import org.vimal.security.v1.util.validation.ValidationsUtil;

import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AdminUserService {
    private final UserModelRepo userModelRepo;
    private final RoleModelRepo roleModelRepo;
    private final PermissionModelRepo permissionModelRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public ResponseEntity<?> createUser(UserCreationDto request) {
        var invalidInputs = InputValidationUtil.validateInputs(request);
        var mapOfErrors = new HashMap<String, Object>();
        if (!invalidInputs.isEmpty()) mapOfErrors.put("invalid_inputs", invalidInputs);
        if (request.getRoles() != null && !request.getRoles().isEmpty()) {
            request.setRoles(request.getRoles().stream().filter(r -> r != null && !r.isBlank()).collect(Collectors.toSet()));
            if (!request.getRoles().isEmpty()) {
                var youAreNotAllowedToAssignTheseRoles = validateRoles(request.getRoles(), CurrentUserUtil.getCurrentAuthenticatedUserHighestAdminRole());
                if (!youAreNotAllowedToAssignTheseRoles.isEmpty())
                    mapOfErrors.put("you_are_not_allowed_to_assign_these_roles", youAreNotAllowedToAssignTheseRoles);
            }
        } else request.setRoles(new HashSet<>());
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        if (userModelRepo.existsByUsername(request.getUsername()))
            invalidInputs.add("Username: '" + request.getUsername() + "' already taken");
        if (userModelRepo.existsByRealEmail(request.getEmail()))
            invalidInputs.add("Email: '" + request.getEmail() + "' already taken");
        if (!invalidInputs.isEmpty()) mapOfErrors.put("invalid_inputs", invalidInputs);
        var resolvedRolesDto = resolveRoles(request.getRoles());
        if (!resolvedRolesDto.getMissingRoles().isEmpty())
            mapOfErrors.put("non_existing_roles", resolvedRolesDto.getMissingRoles());
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        var currentAuthenticatedUser = CurrentUserUtil.getCurrentAuthenticatedUser();
        var userModel = toUserModel(request, resolvedRolesDto.getRoles(), currentAuthenticatedUser);
        return ResponseEntity.ok(
                UserMapperUtil.toSummaryDto(userModelRepo.save(userModel))
        );
    }

    private Set<String> validateRoles(Set<String> roles, String currentUserHighestAdminRole) {
        if (SystemRole.TOP_ROLES.getFirst().equals(currentUserHighestAdminRole) || roles.isEmpty())
            return new HashSet<>();
        var setOfRoles = new HashSet<String>();
        for (String requestedRole : roles) {
            if (SystemRole.TOP_ROLES.contains(requestedRole)) {
                if (currentUserHighestAdminRole == null || SystemRole.TOP_ROLES.indexOf(requestedRole) <= SystemRole.TOP_ROLES.indexOf(currentUserHighestAdminRole))
                    setOfRoles.add(requestedRole);
            }
        }
        return setOfRoles;
    }

    private ResolvedRolesDto resolveRoles(Set<String> roleNames) {
        if (roleNames.isEmpty()) return new ResolvedRolesDto(new HashSet<>(), new HashSet<>());
        var foundRoles = new HashSet<>(roleModelRepo.findAllById(roleNames));
        var foundRoleNames = foundRoles.stream().map(RoleModel::getRoleName).collect(Collectors.toSet());
        var missingRoles = roleNames.stream().filter(name -> !foundRoleNames.contains(name)).collect(Collectors.toSet());
        return new ResolvedRolesDto(foundRoles, missingRoles);
    }

    private UserModel toUserModel(UserCreationDto request,
                                  Set<RoleModel> roles,
                                  UserModel currentAuthenticatedUser) {
        return UserModel.builder()
                .firstName(request.getFirstName())
                .middleName(request.getMiddleName())
                .lastName(request.getLastName())
                .username(request.getUsername())
                .email(request.getEmail())
                .realEmail(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .roles(roles)
                .emailVerified(request.isEmailVerified())
                .accountEnabled(request.isAccountEnabled())
                .accountLocked(request.isAccountLocked())
                .lastLockedAt(request.isAccountLocked() ? Instant.now() : null)
                .createdBy(currentAuthenticatedUser.getUsername())
                .updatedBy(currentAuthenticatedUser.getUsername())
                .build();
    }

    public ResponseEntity<?> createUsers(Set<UserCreationDto> requests) {
        var invalidInputs = new HashSet<String>();
        var roles = new HashSet<String>();
        var duplicateUsernamesInRequest = new HashSet<String>();
        var duplicateEmailsInRequest = new HashSet<String>();
        var usernames = new HashSet<String>();
        var emails = new HashSet<String>();
        requests.forEach(request -> {
            var invalidInputsForThisRequest = InputValidationUtil.validateInputs(request);
            if (!invalidInputsForThisRequest.isEmpty()) invalidInputs.addAll(invalidInputsForThisRequest);
            try {
                ValidationsUtil.validateUsername(request.getUsername());
                if (!usernames.add(request.getUsername())) duplicateUsernamesInRequest.add(request.getUsername());
            } catch (BadRequestExc ignored) {
            }
            if (request.getEmail() != null && ValidationsUtil.EMAIL_PATTERN.matcher(request.getEmail()).matches() && !emails.add(request.getEmail()))
                duplicateEmailsInRequest.add(request.getEmail());
            if (request.getRoles() != null && !request.getRoles().isEmpty()) {
                request.setRoles(request.getRoles().stream().filter(r -> r != null && !r.isBlank()).collect(Collectors.toSet()));
                if (!request.getRoles().isEmpty()) roles.addAll(request.getRoles());
            } else request.setRoles(new HashSet<>());
        });
        var mapOfErrors = new HashMap<String, Object>();
        if (!invalidInputs.isEmpty()) mapOfErrors.put("invalid_inputs", invalidInputs);
        if (!duplicateUsernamesInRequest.isEmpty())
            mapOfErrors.put("duplicate_usernames_in_request", duplicateUsernamesInRequest);
        if (!duplicateEmailsInRequest.isEmpty())
            mapOfErrors.put("duplicate_emails_in_request", duplicateEmailsInRequest);
        var currentUserHighestAdminRole = CurrentUserUtil.getCurrentAuthenticatedUserHighestAdminRole();
        var youAreNotAllowedToAssignTheseRoles = validateRoles(roles, currentUserHighestAdminRole);
        if (!youAreNotAllowedToAssignTheseRoles.isEmpty())
            mapOfErrors.put("you_are_not_allowed_to_assign_these_roles", youAreNotAllowedToAssignTheseRoles);
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        var existingUsersByUsername = userModelRepo.findByUsernameIn(usernames);
        var existingUsersByEmail = userModelRepo.findByEmailIn(emails);
        var usernamesAlreadyTaken = existingUsersByUsername.stream()
                .map(UserModel::getUsername)
                .collect(Collectors.toSet());
        if (!usernamesAlreadyTaken.isEmpty()) mapOfErrors.put("already_taken_usernames", usernamesAlreadyTaken);
        var emailsAlreadyTaken = existingUsersByEmail.stream()
                .map(UserModel::getEmail)
                .collect(Collectors.toSet());
        if (!emailsAlreadyTaken.isEmpty()) mapOfErrors.put("already_taken_emails", emailsAlreadyTaken);
        var resolvedRolesDto = resolveRoles(roles);
        if (!resolvedRolesDto.getMissingRoles().isEmpty())
            mapOfErrors.put("non_existing_roles", resolvedRolesDto.getMissingRoles());
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        var currentAuthenticatedUser = CurrentUserUtil.getCurrentAuthenticatedUser();
        var resolvedRolesMap = resolvedRolesDto.getRoles().stream()
                .collect(Collectors.toMap(RoleModel::getRoleName, Function.identity()));
        var newUsers = requests.stream()
                .map(request -> {
                    if (request.getRoles().isEmpty())
                        return toUserModel(request, new HashSet<>(), currentAuthenticatedUser);
                    var rolesToAssign = request.getRoles().stream()
                            .map(resolvedRolesMap::get)
                            .filter(Objects::nonNull)
                            .collect(Collectors.toSet());
                    return toUserModel(request, rolesToAssign, currentAuthenticatedUser);
                })
                .collect(Collectors.toSet());
        return ResponseEntity.ok(
                userModelRepo.saveAll(newUsers).stream()
                        .map(UserMapperUtil::toSummaryDto)
                        .toList()
        );
    }

    public ResponseEntity<?> deleteUserByUsername(String username) {
        try {
            ValidationsUtil.validateUsername(username);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("User not found with username: '" + username + "'");
        }
        if (CurrentUserUtil.getCurrentAuthenticatedUser().getUsername().equals(username))
            throw new BadRequestExc("You cannot delete your own account using this endpoint");
        var user = userModelRepo.findByUsername(username).orElseThrow(() -> new BadRequestExc("User not found with username: '" + username + "'"));
        var youAreNotAllowedToDeleteUserWithTheseRoles = validateRoles(user, CurrentUserUtil.getCurrentAuthenticatedUserHighestAdminRole());
        if (!youAreNotAllowedToDeleteUserWithTheseRoles.isEmpty())
            return ResponseEntity.badRequest().body(Map.of("you_are_not_allowed_to_delete_user_with_these_roles", youAreNotAllowedToDeleteUserWithTheseRoles));
        jwtUtil.revokeAccessToken(user);
        jwtUtil.revokeRefreshTokenByUser(user);
        userModelRepo.delete(user);
        return ResponseEntity.ok(
                Map.of("message", "User deleted successfully")
        );
    }

    private Set<String> validateRoles(UserModel user, String currentUserHighestAdminRole) {
        return validateRoles(extractRoleNames(user), currentUserHighestAdminRole);
    }

    private Set<String> extractRoleNames(UserModel user) {
        return user.getRoles().stream().map(RoleModel::getRoleName).collect(Collectors.toSet());
    }

    public ResponseEntity<?> deleteUserByEmail(String email) {
        try {
            ValidationsUtil.validateEmail(email);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("User not found with email: '" + email + "'");
        }
        if (CurrentUserUtil.getCurrentAuthenticatedUser().getEmail().equalsIgnoreCase(email))
            throw new BadRequestExc("You cannot delete your own account using this endpoint");
        var userToDelete = userModelRepo.findByEmail(email).orElseThrow(() -> new BadRequestExc("User not found with email: '" + email + "'"));
        var youAreNotAllowedToDeleteUserWithTheseRoles = validateRoles(userToDelete, CurrentUserUtil.getCurrentAuthenticatedUserHighestAdminRole());
        if (!youAreNotAllowedToDeleteUserWithTheseRoles.isEmpty())
            return ResponseEntity.badRequest().body(Map.of("you_are_not_allowed_to_delete_user_with_these_roles", youAreNotAllowedToDeleteUserWithTheseRoles));
        jwtUtil.revokeAccessToken(userToDelete);
        jwtUtil.revokeRefreshTokenByUser(userToDelete);
        userModelRepo.delete(userToDelete);
        return ResponseEntity.ok(
                Map.of("message", "User deleted successfully")
        );
    }

    public ResponseEntity<?> deleteUser(String usernameOrEmail) {
        try {
            ValidationsUtil.validateString(usernameOrEmail, "Username/email");
        } catch (BadRequestExc e) {
            throw new BadRequestExc("User not found with username/email: '" + usernameOrEmail + "'");
        }
        if (ValidationsUtil.EMAIL_PATTERN.matcher(usernameOrEmail).matches()) return deleteUserByEmail(usernameOrEmail);
        else if (ValidationsUtil.USERNAME_PATTERN.matcher(usernameOrEmail).matches())
            return deleteUserByUsername(usernameOrEmail);
        else throw new BadRequestExc("User not found with username/email: '" + usernameOrEmail + "'");
    }

    public ResponseEntity<?> deleteUsers(Set<String> usernamesOrEmails) {
        var usernames = new HashSet<String>();
        var emails = new HashSet<String>();
        var invalidInputs = new HashSet<String>();
        usernamesOrEmails.forEach(identifier -> {
            if (ValidationsUtil.EMAIL_PATTERN.matcher(identifier).matches()) emails.add(identifier);
            else if (ValidationsUtil.USERNAME_PATTERN.matcher(identifier).matches()) usernames.add(identifier);
            else invalidInputs.add(identifier);
        });
        var mapOfErrors = new HashMap<String, Object>();
        if (!invalidInputs.isEmpty()) mapOfErrors.put("users_found_with_these_usernames_or_emails", invalidInputs);
        var currentUser = CurrentUserUtil.getCurrentAuthenticatedUser();
        var ownAccountFoundWithUsernameOrEmail = new HashSet<String>();
        if (usernames.contains(currentUser.getUsername()))
            ownAccountFoundWithUsernameOrEmail.add(currentUser.getUsername());
        if (emails.contains(currentUser.getEmail())) ownAccountFoundWithUsernameOrEmail.add(currentUser.getEmail());
        if (!ownAccountFoundWithUsernameOrEmail.isEmpty())
            mapOfErrors.put("you_cannot_delete_your_own_account_using_this_endpoint", ownAccountFoundWithUsernameOrEmail);
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        var usersByUsername = userModelRepo.findByUsernameIn(usernames);
        var usersByEmail = userModelRepo.findByEmailIn(emails);
        var foundUsernames = usersByUsername.stream().map(UserModel::getUsername).collect(Collectors.toSet());
        usernames.removeAll(foundUsernames);
        if (!usernames.isEmpty()) mapOfErrors.put("not_found_usernames", usernames);
        var foundEmails = usersByEmail.stream().map(UserModel::getEmail).collect(Collectors.toSet());
        emails.removeAll(foundEmails);
        if (!emails.isEmpty()) mapOfErrors.put("not_found_emails", emails);
        if (!usersByEmail.isEmpty()) usersByUsername.addAll(usersByEmail);
        var allRolesNamesOfUsers = usersByUsername.stream()
                .flatMap(user -> user.getRoles().stream())
                .map(RoleModel::getRoleName)
                .collect(Collectors.toSet());
        var youAreNotAllowedToDeleteUsersWithTheseRoles = validateRoles(allRolesNamesOfUsers, CurrentUserUtil.getCurrentAuthenticatedUserHighestAdminRole());
        if (!youAreNotAllowedToDeleteUsersWithTheseRoles.isEmpty())
            mapOfErrors.put("you_are_not_allowed_to_delete_users_with_these_roles", youAreNotAllowedToDeleteUsersWithTheseRoles);
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        jwtUtil.revokeAccessTokens(usersByUsername);
        jwtUtil.revokeRefreshTokensByUsers(usersByUsername);
        userModelRepo.deleteAll(usersByUsername);
        return ResponseEntity.ok(
                Map.of("message", "Users deleted successfully")
        );
    }

    public UserSummaryDto getUserByUsername(String username) {
        try {
            ValidationsUtil.validateUsername(username);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("User not found with username: '" + username + "'");
        }
        var requestedUser = userModelRepo.findByUsername(username).orElseThrow(() -> new BadRequestExc("User not found with username: '" + username + "'"));
        return UserMapperUtil.toSummaryDto(requestedUser);
    }

    public UserSummaryDto getUserByEmail(String email) {
        try {
            ValidationsUtil.validateEmail(email);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("User not found with email: '" + email + "'");
        }
        var requestedUser = userModelRepo.findByEmail(email).orElseThrow(() -> new BadRequestExc("User not found with email: '" + email + "'"));
        return UserMapperUtil.toSummaryDto(requestedUser);
    }

    public ResponseEntity<?> getUser(String usernameOrEmail) {
        try {
            ValidationsUtil.validateString(usernameOrEmail, "Username/email");
        } catch (BadRequestExc e) {
            throw new BadRequestExc("User not found with username/email: '" + usernameOrEmail + "'");
        }
        if (ValidationsUtil.EMAIL_PATTERN.matcher(usernameOrEmail).matches())
            return ResponseEntity.ok(getUserByEmail(usernameOrEmail));
        else if (ValidationsUtil.USERNAME_PATTERN.matcher(usernameOrEmail).matches())
            return ResponseEntity.ok(getUserByUsername(usernameOrEmail));
        else throw new BadRequestExc("User not found with username/email: '" + usernameOrEmail + "'");
    }

    public ResponseEntity<?> getUsers(Set<String> usernamesOrEmails) {
        var usernames = new HashSet<String>();
        var emails = new HashSet<String>();
        var invalidInputs = new HashSet<String>();
        usernamesOrEmails.forEach(identifier -> {
            if (ValidationsUtil.EMAIL_PATTERN.matcher(identifier).matches()) emails.add(identifier);
            else if (ValidationsUtil.USERNAME_PATTERN.matcher(identifier).matches()) usernames.add(identifier);
            else invalidInputs.add(identifier);
        });
        if (!invalidInputs.isEmpty())
            return ResponseEntity.badRequest().body(Map.of("users_found_with_these_usernames_or_emails", invalidInputs));
        var usersByUsername = userModelRepo.findByUsernameIn(usernames);
        var usersByEmail = userModelRepo.findByEmailIn(emails);
        var foundUsernames = usersByUsername.stream().map(UserModel::getUsername).collect(Collectors.toSet());
        var foundEmails = usersByEmail.stream().map(UserModel::getEmail).collect(Collectors.toSet());
        usernames.removeAll(foundUsernames);
        var mapOfErrors = new HashMap<String, Object>();
        if (!usernames.isEmpty()) mapOfErrors.put("not_found_usernames", usernames);
        emails.removeAll(foundEmails);
        if (!emails.isEmpty()) mapOfErrors.put("not_found_emails", emails);
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        if (!usersByEmail.isEmpty()) usersByUsername.addAll(usersByEmail);
        return ResponseEntity.ok(
                usersByUsername.stream()
                        .map(UserMapperUtil::toSummaryDto)
                        .toList()
        );
    }

    public ResponseEntity<?> updateUser(String usernameOrEmail,
                                        UserUpdationDto request) {
        try {
            ValidationsUtil.validateString(usernameOrEmail, "Username/email");
        } catch (BadRequestExc e) {
            throw new BadRequestExc("User not found with username/email: '" + usernameOrEmail + "'");
        }
        var currentAuthenticatedUser = CurrentUserUtil.getCurrentAuthenticatedUser();
        if (currentAuthenticatedUser.getUsername().equals(usernameOrEmail))
            throw new BadRequestExc(usernameOrEmail + "(You cannot modify your own account using this endpoint)");
        if (currentAuthenticatedUser.getEmail().equalsIgnoreCase(usernameOrEmail))
            throw new BadRequestExc(usernameOrEmail + "(You cannot modify your own account using this endpoint)");
        var currentUserHighestAdminRole = CurrentUserUtil.getCurrentAuthenticatedUserHighestAdminRole();
        if (request.getRoles() != null) {
            request.setRoles(request.getRoles().stream().filter(r -> r != null && !r.isBlank()).collect(Collectors.toSet()));
            var youAreNotAllowedToAssignTheseRoles = validateRoles(request.getRoles(), currentUserHighestAdminRole);
            if (!youAreNotAllowedToAssignTheseRoles.isEmpty())
                return ResponseEntity.badRequest().body(Map.of("you_are_not_allowed_to_assign_these_roles", youAreNotAllowedToAssignTheseRoles));
        }
        UserModel existingUser;
        if (ValidationsUtil.EMAIL_PATTERN.matcher(usernameOrEmail).matches())
            existingUser = userModelRepo.findByEmail(usernameOrEmail).orElseThrow(() -> new BadRequestExc("User not found with email: '" + usernameOrEmail + "'"));
        else if (ValidationsUtil.USERNAME_PATTERN.matcher(usernameOrEmail).matches())
            existingUser = userModelRepo.findByUsername(usernameOrEmail).orElseThrow(() -> new BadRequestExc("User not found with username: '" + usernameOrEmail + "'"));
        else throw new BadRequestExc("User not found with username/email: '" + usernameOrEmail + "'");
        var youAreNotAllowedToModifyUserWithTheseRoles = validateRoles(existingUser, currentUserHighestAdminRole);
        var mapOfErrors = new HashMap<String, Object>();
        if (!youAreNotAllowedToModifyUserWithTheseRoles.isEmpty())
            mapOfErrors.put("you_are_not_allowed_to_modify_user_with_these_roles", youAreNotAllowedToModifyUserWithTheseRoles);
        var userModificationDto = validatedAndSetUserDetails(existingUser, request);
        if (!userModificationDto.getInvalidInputs().isEmpty())
            mapOfErrors.put("invalid_inputs", userModificationDto.getInvalidInputs());
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        if (request.getRoles() != null) {
            var resolvedRolesDto = resolveRoles(request.getRoles());
            if (!resolvedRolesDto.getMissingRoles().isEmpty())
                mapOfErrors.put("non_existing_roles", resolvedRolesDto.getMissingRoles());
            if (!existingUser.getRoles().equals(resolvedRolesDto.getRoles())) {
                existingUser.setRoles(resolvedRolesDto.getRoles());
                userModificationDto.setModified(true);
                userModificationDto.setShouldRemoveTokens(true);
            }
        }
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        if (!userModificationDto.isModified())
            return ResponseEntity.ok(
                    Map.of("message", "No changes made to user: '" + existingUser.getUsername() + "'")
            );
        if (userModificationDto.isShouldRemoveTokens()) {
            jwtUtil.revokeAccessToken(existingUser);
            jwtUtil.revokeRefreshTokenByUser(existingUser);
        }
        existingUser.setUpdatedBy(currentAuthenticatedUser.getUsername());
        return ResponseEntity.ok(
                UserMapperUtil.toSummaryDto(userModelRepo.save(existingUser))
        );
    }

    private UserModificationDto validatedAndSetUserDetails(UserModel userToUpdate, UserUpdationDto request) {
        var userModificationDto = validateAndSetUserDetailsBasic(userToUpdate, request);
        if (request.getEmail() != null && !request.getEmail().equals(userToUpdate.getEmail())) {
            try {
                ValidationsUtil.validateEmail(request.getEmail());
                if (userModelRepo.existsByRealEmail(request.getEmail()))
                    userModificationDto.getInvalidInputs().add("Email: '" + request.getEmail() + "' already taken");
                else {
                    userToUpdate.setEmail(request.getEmail());
                    userToUpdate.setRealEmail(request.getEmail());
                    userModificationDto.setModified(true);
                    userModificationDto.setShouldRemoveTokens(true);
                }
            } catch (BadRequestExc e) {
                userModificationDto.getInvalidInputs().add(e.getMessage());
            }
        }
        if (request.getUsername() != null && !request.getUsername().equals(userToUpdate.getUsername())) {
            try {
                ValidationsUtil.validateUsername(request.getUsername());
                if (userModelRepo.existsByUsername(request.getUsername()))
                    userModificationDto.getInvalidInputs().add("Username: '" + request.getUsername() + "' already taken");
                else {
                    userToUpdate.setUsername(request.getUsername());
                    userModificationDto.setModified(true);
                    userModificationDto.setShouldRemoveTokens(true);
                }
            } catch (BadRequestExc e) {
                userModificationDto.getInvalidInputs().add(e.getMessage());
            }
        }
        return userModificationDto;
    }

    private UserModificationDto validateAndSetUserDetailsBasic(UserModel userToUpdate, UserUpdationDto request) {
        var userModificationDto = new UserModificationDto(false, false, new HashSet<>());
        if (request.isAccountEnabled() != userToUpdate.isAccountEnabled()) {
            userToUpdate.setAccountEnabled(request.isAccountEnabled());
            userModificationDto.setModified(true);
            userModificationDto.setShouldRemoveTokens(true);
        }
        if (request.isAccountLocked() != userToUpdate.isAccountLocked()) {
            userToUpdate.setAccountLocked(request.isAccountLocked());
            userModificationDto.setModified(true);
            userModificationDto.setShouldRemoveTokens(true);
        }
        if (request.isEmailVerified() != userToUpdate.isEmailVerified()) {
            userToUpdate.setEmailVerified(request.isEmailVerified());
            userModificationDto.setModified(true);
            userModificationDto.setShouldRemoveTokens(true);
        }
        if (request.getFirstName() != null && !request.getFirstName().equals(userToUpdate.getFirstName())) {
            try {
                ValidationsUtil.validateFirstName(request.getFirstName());
                userToUpdate.setFirstName(request.getFirstName());
                userModificationDto.setModified(true);
            } catch (BadRequestExc e) {
                userModificationDto.getInvalidInputs().add(e.getMessage());
            }
        }
        if (request.getMiddleName() != null && !request.getMiddleName().equals(userToUpdate.getMiddleName())) {
            try {
                ValidationsUtil.validateMiddleName(request.getMiddleName());
                userToUpdate.setMiddleName(request.getMiddleName());
                userModificationDto.setModified(true);
            } catch (BadRequestExc e) {
                userModificationDto.getInvalidInputs().add(e.getMessage());
            }
        }
        if (request.getLastName() != null && !request.getLastName().equals(userToUpdate.getLastName())) {
            try {
                ValidationsUtil.validateLastName(request.getLastName());
                userToUpdate.setLastName(request.getLastName());
                userModificationDto.setModified(true);
            } catch (BadRequestExc e) {
                userModificationDto.getInvalidInputs().add(e.getMessage());
            }
        }
        if (request.getPassword() != null) {
            try {
                ValidationsUtil.validatePassword(request.getPassword());
                userToUpdate.setPassword(passwordEncoder.encode(request.getPassword()));
                userModificationDto.setModified(true);
            } catch (BadRequestExc e) {
                userModificationDto.getInvalidInputs().add(e.getMessage());
            }
        }
        return userModificationDto;
    }

    public ResponseEntity<?> updateUsers(Set<UserUpdationDto> requests) {
        var usernames = new HashSet<String>();
        var emails = new HashSet<String>();
        var invalidUsernames = new HashSet<String>();
        var duplicateUsernames = new HashSet<String>();
        var duplicateEmails = new HashSet<String>();
        var roles = new HashSet<String>();
        requests.forEach(request -> {
            try {
                ValidationsUtil.validateUsername(request.getUsername());
                if (!usernames.add(request.getUsername())) duplicateUsernames.add(request.getUsername());
            } catch (BadRequestExc e) {
                invalidUsernames.add(request.getUsername());
            }
            if (request.getEmail() != null && ValidationsUtil.EMAIL_PATTERN.matcher(request.getEmail()).matches() && !emails.add(request.getEmail()))
                duplicateEmails.add(request.getEmail());
            if (request.getRoles() != null && !request.getRoles().isEmpty()) {
                request.setRoles(request.getRoles().stream().filter(r -> r != null && !r.isBlank()).collect(Collectors.toSet()));
                if (!request.getRoles().isEmpty()) roles.addAll(request.getRoles());
            }
        });
        var mapOfErrors = new HashMap<String, Object>();
        if (!invalidUsernames.isEmpty()) mapOfErrors.put("users_not_found_with_these_usernames", invalidUsernames);
        if (!duplicateUsernames.isEmpty()) mapOfErrors.put("duplicate_usernames_in_request", duplicateUsernames);
        if (!duplicateEmails.isEmpty()) mapOfErrors.put("duplicate_emails_in_request", duplicateEmails);
        var currentAuthenticatedUser = CurrentUserUtil.getCurrentAuthenticatedUser();
        if (usernames.contains(currentAuthenticatedUser.getUsername()))
            mapOfErrors.put("you_cannot_update_your_own_account_using_this_endpoint", currentAuthenticatedUser.getUsername());
        var currentUserHighestAdminRole = CurrentUserUtil.getCurrentAuthenticatedUserHighestAdminRole();
        var youAreNotAllowedToAssignTheseRoles = validateRoles(roles, currentUserHighestAdminRole);
        if (!youAreNotAllowedToAssignTheseRoles.isEmpty())
            mapOfErrors.put("you_are_not_allowed_to_assign_these_roles", youAreNotAllowedToAssignTheseRoles);
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        var existingUsers = userModelRepo.findByUsernameIn(usernames);
        var existingUsersByEmail = userModelRepo.findByEmailIn(emails);
        var requestedEmailToUsername = requests.stream()
                .filter(r -> r.getEmail() != null)
                .collect(Collectors.toMap(
                        r -> r.getEmail().toLowerCase(),
                        UserUpdationDto::getUsername,
                        (u1, u2) -> u1
                ));
        var conflictingEmails = existingUsersByEmail.stream()
                .filter(user -> {
                    var requesterForThisEmail = requestedEmailToUsername.get(user.getEmail().toLowerCase());
                    return requesterForThisEmail != null && !user.getUsername().equals(requesterForThisEmail);
                })
                .map(UserModel::getEmail)
                .collect(Collectors.toSet());
        if (!conflictingEmails.isEmpty())
            mapOfErrors.put("emails_that_already_taken_by_other_users", conflictingEmails);
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        var resolvedRolesDto = resolveRoles(roles);
        if (!resolvedRolesDto.getMissingRoles().isEmpty())
            mapOfErrors.put("non_existing_roles", resolvedRolesDto.getMissingRoles());
        var userMap = existingUsers.stream().collect(Collectors.toMap(UserModel::getUsername, Function.identity()));
        var updatedUsers = new HashSet<UserModel>();
        var usersToWhichWeHaveToRevokeTokens = new HashSet<UserModel>();
        var notFoundUsers = new HashSet<String>();
        var youCannotModifyUsersWithTheseRoles = new HashSet<String>();
        var invalidInputs = new HashSet<String>();
        var resolvedRolesMap = resolvedRolesDto.getRoles().stream().collect(Collectors.toMap(RoleModel::getRoleName, Function.identity()));
        requests.forEach(request -> {
                    var userToUpdate = userMap.get(request.getUsername());
                    if (userToUpdate == null) {
                        notFoundUsers.add(request.getUsername());
                        return;
                    }
                    var userModificationDto = validateAndSetUserDetailsBasic(userToUpdate, request);
                    if (request.getEmail() != null && !request.getEmail().equals(userToUpdate.getEmail())) {
                        try {
                            ValidationsUtil.validateEmail(request.getEmail());
                            userToUpdate.setEmail(request.getEmail());
                            userToUpdate.setRealEmail(request.getEmail());
                            userModificationDto.setModified(true);
                            userModificationDto.setShouldRemoveTokens(true);
                        } catch (BadRequestExc e) {
                            userModificationDto.getInvalidInputs().add(e.getMessage());
                        }
                    }
                    if (!userModificationDto.getInvalidInputs().isEmpty())
                        invalidInputs.addAll(userModificationDto.getInvalidInputs());
                    var youCannotModifyUserWithTheseRoles = validateRoles(userToUpdate, currentUserHighestAdminRole);
                    if (!youCannotModifyUserWithTheseRoles.isEmpty()) {
                        youCannotModifyUsersWithTheseRoles.addAll(youCannotModifyUserWithTheseRoles);
                        return;
                    }
                    if (request.getRoles() != null) {
                        var rolesToAssign = request.getRoles().stream()
                                .map(resolvedRolesMap::get)
                                .filter(Objects::nonNull)
                                .collect(Collectors.toSet());
                        if (!userToUpdate.getRoles().equals(rolesToAssign)) {
                            userToUpdate.setRoles(rolesToAssign);
                            userModificationDto.setModified(true);
                            userModificationDto.setShouldRemoveTokens(true);
                        }
                    }
                    if (userModificationDto.isModified()) {
                        userToUpdate.setUpdatedBy(currentAuthenticatedUser.getUsername());
                        if (userModificationDto.isShouldRemoveTokens()) {
                            usersToWhichWeHaveToRevokeTokens.add(userToUpdate);
                        } else updatedUsers.add(userToUpdate);
                    }
                }
        );
        if (!notFoundUsers.isEmpty()) mapOfErrors.put("not_found_usernames", notFoundUsers);
        if (!youCannotModifyUsersWithTheseRoles.isEmpty())
            mapOfErrors.put("you_cannot_modify_users_with_these_roles", youCannotModifyUsersWithTheseRoles);
        if (!invalidInputs.isEmpty()) mapOfErrors.put("invalid_inputs", invalidInputs);
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        if (updatedUsers.isEmpty() && usersToWhichWeHaveToRevokeTokens.isEmpty()) return ResponseEntity.ok(
                Map.of("message", "No users updated")
        );
        if (!usersToWhichWeHaveToRevokeTokens.isEmpty()) {
            jwtUtil.revokeAccessTokens(usersToWhichWeHaveToRevokeTokens);
            jwtUtil.revokeRefreshTokensByUsers(usersToWhichWeHaveToRevokeTokens);
            updatedUsers.addAll(usersToWhichWeHaveToRevokeTokens);
        }
        return ResponseEntity.ok(
                userModelRepo.saveAll(updatedUsers).stream()
                        .map(UserMapperUtil::toSummaryDto)
                        .toList()
        );
    }

    public PermissionModel getPermission(String permissionName) {
        try {
            ValidationsUtil.validatePermissionName(permissionName);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Permission not found: '" + permissionName + "'");
        }
        return permissionModelRepo.findById(permissionName).orElseThrow(() -> new BadRequestExc("Permission not found: '" + permissionName + "'"));
    }

    public ResponseEntity<?> getPermissions(Set<String> permissionNames) {
        var invalidInputs = new HashSet<String>();
        permissionNames.forEach(permissionName -> {
            try {
                ValidationsUtil.validatePermissionName(permissionName);
            } catch (BadRequestExc e) {
                invalidInputs.add(e.getMessage());
            }
        });
        if (!invalidInputs.isEmpty())
            return ResponseEntity.badRequest().body(Map.of("not_found_permissions", invalidInputs));
        var permissions = permissionModelRepo.findAllById(permissionNames);
        var foundPermissionNames = permissions.stream().map(PermissionModel::getPermissionName).collect(Collectors.toSet());
        var notFound = permissionNames.stream().filter(name -> !foundPermissionNames.contains(name)).collect(Collectors.toSet());
        if (!notFound.isEmpty()) return ResponseEntity.badRequest().body(Map.of("not_found_permissions", notFound));
        return ResponseEntity.ok(
                permissions
        );
    }

    public ResponseEntity<?> createRole(RoleCreationDto role) {
        var invalidInputs = InputValidationUtil.validateInputs(role);
        if (!invalidInputs.isEmpty()) return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        if (roleModelRepo.existsById(role.getRoleName()))
            throw new BadRequestExc("Role: '" + role.getRoleName() + "' already exists");
        if (role.getPermissions() != null && !role.getPermissions().isEmpty())
            role.setPermissions(role.getPermissions().stream().filter(p -> p != null && !p.isBlank()).collect(Collectors.toSet()));
        else role.setPermissions(new HashSet<>());
        var resolvedPermissionsDto = resolvePermissions(role.getPermissions());
        if (!resolvedPermissionsDto.getMissingPermissions().isEmpty())
            return ResponseEntity.badRequest().body(Map.of("non_existing_permissions", resolvedPermissionsDto.getMissingPermissions()));
        return ResponseEntity.ok(
                RoleMapperUtil.toSummaryDto(
                        roleModelRepo.save(
                                toRoleModel(role, resolvedPermissionsDto.getPermissions(), CurrentUserUtil.getCurrentAuthenticatedUser())
                        )
                )
        );
    }

    private ResolvedPermissionsDto resolvePermissions(Set<String> permissionNames) {
        if (permissionNames.isEmpty()) return new ResolvedPermissionsDto(new HashSet<>(), new HashSet<>());
        var foundPermissions = new HashSet<>(permissionModelRepo.findAllById(permissionNames));
        var foundPermissionNames = foundPermissions.stream()
                .map(PermissionModel::getPermissionName)
                .collect(Collectors.toSet());
        var missingPermissions = permissionNames.stream()
                .filter(name -> !foundPermissionNames.contains(name))
                .collect(Collectors.toSet());
        return new ResolvedPermissionsDto(foundPermissions, missingPermissions);
    }

    private RoleModel toRoleModel(RoleCreationDto role,
                                  Set<PermissionModel> permissions,
                                  UserModel currentAuthenticatedUser) {
        return RoleModel.builder()
                .roleName(role.getRoleName())
                .description(role.getDescription())
                .permissions(permissions)
                .createdBy(currentAuthenticatedUser.getUsername())
                .updatedBy(currentAuthenticatedUser.getUsername())
                .build();
    }

    public ResponseEntity<?> createRoles(Set<RoleCreationDto> roles) {
        var duplicateRoleNames = new HashSet<String>();
        var roleNames = new HashSet<String>();
        var invalidInputs = new HashSet<String>();
        var allPermissionNames = new HashSet<String>();
        roles.forEach(role -> {
            var invalidInputsForThisRequest = InputValidationUtil.validateInputs(role);
            if (!invalidInputsForThisRequest.isEmpty()) invalidInputs.addAll(invalidInputsForThisRequest);
            try {
                ValidationsUtil.validateRoleName(role.getRoleName());
                if (!roleNames.add(role.getRoleName())) duplicateRoleNames.add(role.getRoleName());
            } catch (BadRequestExc ignored) {
            }
            if (role.getPermissions() != null && !role.getPermissions().isEmpty()) {
                role.setPermissions(role.getPermissions().stream().filter(p -> p != null && !p.isBlank()).collect(Collectors.toSet()));
                if (!role.getPermissions().isEmpty()) allPermissionNames.addAll(role.getPermissions());
            } else role.setPermissions(new HashSet<>());
        });
        var mapOfErrors = new HashMap<String, Object>();
        if (!invalidInputs.isEmpty()) mapOfErrors.put("invalid_inputs", invalidInputs);
        if (!duplicateRoleNames.isEmpty()) mapOfErrors.put("duplicate_role_names", duplicateRoleNames);
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        var existingRoles = roleModelRepo.findAllById(roleNames).stream().map(RoleModel::getRoleName).collect(Collectors.toSet());
        if (!existingRoles.isEmpty()) mapOfErrors.put("already_existing_roles", existingRoles);
        var resolvedPermissionsDto = resolvePermissions(allPermissionNames);
        if (!resolvedPermissionsDto.getMissingPermissions().isEmpty())
            mapOfErrors.put("non_existing_permissions", resolvedPermissionsDto.getMissingPermissions());
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        var resolvedPermissionsMap = resolvedPermissionsDto.getPermissions().stream().collect(Collectors.toMap(PermissionModel::getPermissionName, Function.identity()));
        var currentUser = CurrentUserUtil.getCurrentAuthenticatedUser();
        var newRoles = roles.stream()
                .map(role -> {
                    if (role.getPermissions().isEmpty()) return toRoleModel(role, new HashSet<>(), currentUser);
                    return toRoleModel(
                            role,
                            role.getPermissions().stream()
                                    .map(resolvedPermissionsMap::get)
                                    .filter(Objects::nonNull)
                                    .collect(Collectors.toSet())
                            , currentUser
                    );
                })
                .collect(Collectors.toSet());
        return ResponseEntity.ok(
                roleModelRepo.saveAll(newRoles).stream()
                        .map(RoleMapperUtil::toSummaryDto)
                        .toList()
        );
    }

    public Map<String, String> deleteRole(String roleName) {
        try {
            ValidationsUtil.validateRoleName(roleName);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Role: '" + roleName + "' not found");
        }
        var role = roleModelRepo.findById(roleName).orElseThrow(() -> new BadRequestExc("Role: '" + roleName + "' not found"));
        if (role.isSystemRole()) throw new BadRequestExc("You cannot delete system role");
        var userCount = userModelRepo.countByRoles_RoleName(roleName);
        if (userCount > 0)
            throw new BadRequestExc(roleName + " (" + userCount + " user(s)) You cannot delete roles that are assigned to users");
        roleModelRepo.delete(role);
        return Map.of("message", "Role deleted successfully");
    }

    public ResponseEntity<?> deleteRoles(Set<String> roleNames) {
        var invalidInputs = new HashSet<String>();
        roleNames.forEach(roleName -> {
            try {
                ValidationsUtil.validateRoleName(roleName);
            } catch (BadRequestExc e) {
                invalidInputs.add(e.getMessage());
            }
        });
        if (!invalidInputs.isEmpty()) return ResponseEntity.badRequest().body(Map.of("not_found_roles", invalidInputs));
        var rolesToDelete = roleModelRepo.findAllById(roleNames);
        var foundRoleNames = new HashSet<String>();
        var systemRoles = new HashSet<String>();
        var roleUsageCount = new HashSet<String>();
        rolesToDelete.forEach(role -> {
            foundRoleNames.add(role.getRoleName());
            if (role.isSystemRole()) systemRoles.add(role.getRoleName());
            var count = userModelRepo.countByRoles_RoleName(role.getRoleName());
            if (count > 0) roleUsageCount.add(role.getRoleName() + "(" + count + " user(s))");
        });
        var notFoundRoleNames = roleNames.stream().filter(name -> !foundRoleNames.contains(name))
                .collect(Collectors.toSet());
        var mapOfErrors = new HashMap<String, Object>();
        if (!notFoundRoleNames.isEmpty()) mapOfErrors.put("not_found_roles", notFoundRoleNames);
        if (!systemRoles.isEmpty()) mapOfErrors.put("cannot_delete_system_roles", systemRoles);
        if (!roleUsageCount.isEmpty()) mapOfErrors.put("cannot_delete_roles_assigned_to_users", roleUsageCount);
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        roleModelRepo.deleteAll(rolesToDelete);
        return ResponseEntity.ok(
                Map.of("message", "Roles deleted successfully")
        );
    }

    public RoleSummaryDto getRole(String roleName) {
        try {
            ValidationsUtil.validateRoleName(roleName);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Role: '" + roleName + "' not found");
        }
        var role = roleModelRepo.findById(roleName).orElseThrow(() -> new BadRequestExc("Role: '" + roleName + "' not found"));
        return RoleMapperUtil.toSummaryDto(role);
    }

    public ResponseEntity<?> getRoles(Set<String> roleNames) {
        var invalidInputs = new HashSet<String>();
        roleNames.forEach(roleName -> {
            try {
                ValidationsUtil.validateRoleName(roleName);
            } catch (BadRequestExc e) {
                invalidInputs.add(e.getMessage());
            }
        });
        if (!invalidInputs.isEmpty()) return ResponseEntity.badRequest().body(Map.of("not_found_roles", invalidInputs));
        var roles = roleModelRepo.findAllById(roleNames);
        var foundRoleNames = roles.stream()
                .map(RoleModel::getRoleName)
                .collect(Collectors.toSet());
        roleNames.removeAll(foundRoleNames);
        if (!roleNames.isEmpty()) return ResponseEntity.badRequest().body(Map.of("not_found_roles", roleNames));
        return ResponseEntity.ok(
                roles.stream()
                        .map(RoleMapperUtil::toSummaryDto)
                        .toList()
        );
    }

    public ResponseEntity<?> updateRole(RoleCreationDto role) {
        try {
            ValidationsUtil.validateRoleName(role.getRoleName());
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Role: '" + role.getRoleName() + "' not found");
        }
        var existingRole = roleModelRepo.findById(role.getRoleName()).orElseThrow(() -> new BadRequestExc("Role: '" + role.getRoleName() + "' not found"));
        if (existingRole.isSystemRole())
            throw new BadRequestExc("Cannot modify system role: '" + existingRole.getRoleName() + "'");
        var mapOfErrors = new HashMap<String, Object>();
        var roleModificationDto = validateAndSetRoleDetails(existingRole, role);
        if (!roleModificationDto.getInvalidInputs().isEmpty())
            mapOfErrors.put("invalid_inputs", roleModificationDto.getInvalidInputs());
        if (role.getPermissions() != null) {
            role.setPermissions(role.getPermissions().stream().filter(p -> p != null && !p.isBlank()).collect(Collectors.toSet()));
            var resolvedPermissionsDto = resolvePermissions(role.getPermissions());
            if (!resolvedPermissionsDto.getMissingPermissions().isEmpty()) {
                mapOfErrors.put("non_existing_permissions", resolvedPermissionsDto.getMissingPermissions());
                return ResponseEntity.badRequest().body(mapOfErrors);
            }
            if (!existingRole.getPermissions().equals(resolvedPermissionsDto.getPermissions())) {
                existingRole.setPermissions(resolvedPermissionsDto.getPermissions());
                roleModificationDto.setModified(true);
                roleModificationDto.setShouldRemoveTokensOfUsersHavingThisRole(true);
            }
        }
        if (!roleModificationDto.isModified()) return ResponseEntity.ok(
                Map.of("message", "No changes made to role: '" + existingRole.getRoleName() + "'")
        );
        if (roleModificationDto.isShouldRemoveTokensOfUsersHavingThisRole()) {
            var usersWithThisRole = userModelRepo.findByRoles(existingRole);
            if (!usersWithThisRole.isEmpty()) {
                jwtUtil.revokeAccessTokens(usersWithThisRole);
                jwtUtil.revokeRefreshTokensByUsers(usersWithThisRole);
            }
        }
        existingRole.setUpdatedBy(CurrentUserUtil.getCurrentAuthenticatedUser().getUsername());
        return ResponseEntity.ok(
                RoleMapperUtil.toSummaryDto(roleModelRepo.save(existingRole))
        );
    }

    private RoleModificationDto validateAndSetRoleDetails(RoleModel roleToUpdate, RoleCreationDto request) {
        var roleModificationDto = new RoleModificationDto(false, false, new HashSet<>());
        if (request.getDescription() != null && !roleToUpdate.getDescription().equals(request.getDescription())) {
            try {
                ValidationsUtil.validateDescription(request.getDescription());
                roleToUpdate.setDescription(request.getDescription());
                roleModificationDto.setModified(true);
            } catch (BadRequestExc e) {
                roleModificationDto.getInvalidInputs().add(e.getMessage());
            }
        }
        return roleModificationDto;
    }

    public ResponseEntity<?> updateRoles(Set<RoleCreationDto> roles) {
        var duplicateRoleNamesInRequest = new HashSet<String>();
        var roleNames = new HashSet<String>();
        var permissionNames = new HashSet<String>();
        var invalidRoleNames = new HashSet<String>();
        roles.forEach(role -> {
            try {
                ValidationsUtil.validateRoleName(role.getRoleName());
                if (!roleNames.add(role.getRoleName())) duplicateRoleNamesInRequest.add(role.getRoleName());
            } catch (BadRequestExc e) {
                invalidRoleNames.add(role.getRoleName());
            }
            if (role.getPermissions() != null && !role.getPermissions().isEmpty()) {
                role.setPermissions(role.getPermissions().stream().filter(p -> p != null && !p.isBlank()).collect(Collectors.toSet()));
                if (!role.getPermissions().isEmpty()) permissionNames.addAll(role.getPermissions());
            }
        });
        var mapOfErrors = new HashMap<String, Object>();
        if (!invalidRoleNames.isEmpty()) mapOfErrors.put("not_found_rolenames", invalidRoleNames);
        if (!duplicateRoleNamesInRequest.isEmpty())
            mapOfErrors.put("duplicate_role_names", duplicateRoleNamesInRequest);
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        var resolvedPermissionsDto = resolvePermissions(permissionNames);
        if (!resolvedPermissionsDto.getMissingPermissions().isEmpty())
            return ResponseEntity.badRequest().body(Map.of("non_existing_permissions", resolvedPermissionsDto.getMissingPermissions()));
        var resolvedPermissionsMap = resolvedPermissionsDto.getPermissions().stream().collect(Collectors.toMap(PermissionModel::getPermissionName, Function.identity()));
        var existingRoles = roleModelRepo.findAllById(roleNames);
        var roleMap = existingRoles.stream().collect(Collectors.toMap(RoleModel::getRoleName, Function.identity()));
        var updatedRoles = new HashSet<RoleModel>();
        var rolesForWhichWeHaveToRevokeTokensOfUsersWhoHaveTheseRoles = new HashSet<RoleModel>();
        var notFoundRoleNames = new HashSet<String>();
        var systemRoles = new HashSet<String>();
        var currentUser = CurrentUserUtil.getCurrentAuthenticatedUser();
        roles.forEach(role -> {
                    var roleToUpdate = roleMap.get(role.getRoleName());
                    if (roleToUpdate == null) {
                        notFoundRoleNames.add(role.getRoleName());
                        return;
                    }
                    if (roleToUpdate.isSystemRole()) {
                        systemRoles.add(roleToUpdate.getRoleName());
                        return;
                    }
                    var roleModificationDto = validateAndSetRoleDetails(roleToUpdate, role);
                    if (role.getPermissions() != null) {
                        var permissionsToAssign = role.getPermissions().stream()
                                .map(resolvedPermissionsMap::get)
                                .filter(Objects::nonNull)
                                .collect(Collectors.toSet());
                        if (!roleToUpdate.getPermissions().equals(permissionsToAssign)) {
                            roleToUpdate.setPermissions(permissionsToAssign);
                            roleModificationDto.setModified(true);
                            roleModificationDto.setShouldRemoveTokensOfUsersHavingThisRole(true);
                        }
                    }
                    if (roleModificationDto.isModified()) {
                        roleToUpdate.setUpdatedBy(currentUser.getUsername());
                        if (roleModificationDto.isShouldRemoveTokensOfUsersHavingThisRole())
                            rolesForWhichWeHaveToRevokeTokensOfUsersWhoHaveTheseRoles.add(roleToUpdate);
                        else updatedRoles.add(roleToUpdate);
                    }
                }
        );
        if (!systemRoles.isEmpty()) mapOfErrors.put("cannot_modify_system_roles", systemRoles);
        if (!notFoundRoleNames.isEmpty()) mapOfErrors.put("not_found_roles", notFoundRoleNames);
        if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
        if (updatedRoles.isEmpty() && rolesForWhichWeHaveToRevokeTokensOfUsersWhoHaveTheseRoles.isEmpty())
            return ResponseEntity.ok(
                    Map.of("message", "No roles updated")
            );
        if (!rolesForWhichWeHaveToRevokeTokensOfUsersWhoHaveTheseRoles.isEmpty()) {
            var usersWithTheseRoles = userModelRepo.findByRolesIn(rolesForWhichWeHaveToRevokeTokensOfUsersWhoHaveTheseRoles);
            if (!usersWithTheseRoles.isEmpty()) {
                jwtUtil.revokeAccessTokens(usersWithTheseRoles);
                jwtUtil.revokeRefreshTokensByUsers(usersWithTheseRoles);
            }
            updatedRoles.addAll(rolesForWhichWeHaveToRevokeTokensOfUsersWhoHaveTheseRoles);
        }
        return ResponseEntity.ok(
                roleModelRepo.saveAll(updatedRoles).stream()
                        .map(RoleMapperUtil::toSummaryDto)
                        .toList()
        );
    }

    public Page<UserSummaryDto> getAllUsers(Pageable pageable) {
        var users = userModelRepo.findAll(pageable);
        return users.map(UserMapperUtil::toSummaryDto);
    }

    public Page<PermissionModel> getAllPermissions(Pageable pageable) {
        return permissionModelRepo.findAll(pageable);
    }

    public Page<RoleSummaryDto> getAllRoles(Pageable pageable) {
        var roles = roleModelRepo.findAll(pageable);
        return roles.map(RoleMapperUtil::toSummaryDto);
    }

    public ResponseEntity<?> enableEmailMfaForUser(String usernameOrEmail) {
        try {
            ValidationsUtil.validateString(usernameOrEmail, "Username/email");
        } catch (BadRequestExc e) {
            throw new BadRequestExc("User not found with username/email: '" + usernameOrEmail + "'");
        }
        var currentAuthenticatedUser = CurrentUserUtil.getCurrentAuthenticatedUser();
        if (currentAuthenticatedUser.getUsername().equals(usernameOrEmail))
            throw new BadRequestExc(usernameOrEmail + "(You cannot modify your own account using this endpoint)");
        if (currentAuthenticatedUser.getEmail().equalsIgnoreCase(usernameOrEmail))
            throw new BadRequestExc(usernameOrEmail + "(You cannot modify your own account using this endpoint)");
        UserModel existingUser;
        if (ValidationsUtil.EMAIL_PATTERN.matcher(usernameOrEmail).matches())
            existingUser = userModelRepo.findByEmail(usernameOrEmail).orElseThrow(() -> new BadRequestExc("User not found with email: '" + usernameOrEmail + "'"));
        else if (ValidationsUtil.USERNAME_PATTERN.matcher(usernameOrEmail).matches())
            existingUser = userModelRepo.findByUsername(usernameOrEmail).orElseThrow(() -> new BadRequestExc("User not found with username: '" + usernameOrEmail + "'"));
        else throw new BadRequestExc("User not found with username/email: '" + usernameOrEmail + "'");
        var youAreNotAllowedToModifyUserWithTheseRoles = validateRoles(existingUser, CurrentUserUtil.getCurrentAuthenticatedUserHighestAdminRole());
        if (!youAreNotAllowedToModifyUserWithTheseRoles.isEmpty())
            return ResponseEntity.badRequest().body(Map.of("you_are_not_allowed_to_modify_user_with_these_roles", youAreNotAllowedToModifyUserWithTheseRoles));
        if (existingUser.hasMfaEnabled(UserModel.MfaType.EMAIL))
            throw new BadRequestExc("Email MFA is already enabled for user: '" + usernameOrEmail + "'");
        existingUser.enableMfaMethod(UserModel.MfaType.EMAIL);
        existingUser.setUpdatedBy(currentAuthenticatedUser.getUsername());
        jwtUtil.revokeAccessToken(existingUser);
        jwtUtil.revokeRefreshTokenByUser(existingUser);
        return ResponseEntity.ok(
                Map.of(
                        "message", "Email MFA enabled successfully",
                        "user", UserMapperUtil.toSummaryDto(userModelRepo.save(existingUser))
                )
        );
    }

    public ResponseEntity<?> disableEmailMfaForUser(String usernameOrEmail) {
        try {
            ValidationsUtil.validateString(usernameOrEmail, "Username/email");
        } catch (BadRequestExc e) {
            throw new BadRequestExc("User not found with username/email: '" + usernameOrEmail + "'");
        }
        var currentAuthenticatedUser = CurrentUserUtil.getCurrentAuthenticatedUser();
        if (currentAuthenticatedUser.getUsername().equals(usernameOrEmail))
            throw new BadRequestExc(usernameOrEmail + "(You cannot modify your own account using this endpoint)");
        if (currentAuthenticatedUser.getEmail().equalsIgnoreCase(usernameOrEmail))
            throw new BadRequestExc(usernameOrEmail + "(You cannot modify your own account using this endpoint)");
        UserModel existingUser;
        if (ValidationsUtil.EMAIL_PATTERN.matcher(usernameOrEmail).matches())
            existingUser = userModelRepo.findByEmail(usernameOrEmail).orElseThrow(() -> new BadRequestExc("User not found with email: '" + usernameOrEmail + "'"));
        else if (ValidationsUtil.USERNAME_PATTERN.matcher(usernameOrEmail).matches())
            existingUser = userModelRepo.findByUsername(usernameOrEmail).orElseThrow(() -> new BadRequestExc("User not found with username: '" + usernameOrEmail + "'"));
        else throw new BadRequestExc("User not found with username/email: '" + usernameOrEmail + "'");
        var youAreNotAllowedToModifyUserWithTheseRoles = validateRoles(existingUser, CurrentUserUtil.getCurrentAuthenticatedUserHighestAdminRole());
        if (!youAreNotAllowedToModifyUserWithTheseRoles.isEmpty())
            return ResponseEntity.badRequest().body(Map.of("you_are_not_allowed_to_modify_user_with_these_roles", youAreNotAllowedToModifyUserWithTheseRoles));
        if (!existingUser.hasMfaEnabled(UserModel.MfaType.EMAIL))
            throw new BadRequestExc("Email MFA is already disabled for user: '" + usernameOrEmail + "'");
        existingUser.disableMfaMethod(UserModel.MfaType.EMAIL);
        existingUser.setUpdatedBy(currentAuthenticatedUser.getUsername());
        jwtUtil.revokeAccessToken(existingUser);
        jwtUtil.revokeRefreshTokenByUser(existingUser);
        return ResponseEntity.ok(
                Map.of(
                        "message", "Email MFA disabled successfully",
                        "user", UserMapperUtil.toSummaryDto(userModelRepo.save(existingUser))
                )
        );
    }

    public Map<Object, Object> createUsersLenient(Set<UserCreationDto> requests) {
        Set<UserCreationDto> validRequests = new HashSet<>();
        var usernames = new HashSet<String>();
        var emails = new HashSet<String>();
        var skipped = new HashSet<>();
        var allRoles = new HashSet<String>();
        var currentUserHighestAdminRole = CurrentUserUtil.getCurrentAuthenticatedUserHighestAdminRole();
        for (var request : requests) {
            var invalidInputs = InputValidationUtil.validateInputs(request);
            if (!invalidInputs.isEmpty()) {
                skipped.add(Map.of(
                        "request", request,
                        "message", "Skipping request as it has invalid inputs",
                        "invalid_inputs", invalidInputs
                ));
                continue;
            }
            if (!usernames.add(request.getUsername())) {
                skipped.add(Map.of(
                        "request", request,
                        "message", "Skipping request as same username found in previous requests",
                        "same_username_in_previous_requests", request.getUsername()
                ));
                continue;
            }
            if (!emails.add(request.getEmail())) {
                skipped.add(Map.of(
                        "request", request,
                        "message", "Skipping request as same email found in previous requests",
                        "same_email_in_previous_requests", request.getEmail()
                ));
                continue;
            }
            if (request.getRoles() != null && !request.getRoles().isEmpty()) {
                request.setRoles(request.getRoles().stream().filter(r -> r != null && !r.isBlank()).collect(Collectors.toSet()));
                if (!request.getRoles().isEmpty()) {
                    var youAreNotAllowedToAssignTheseRoles = validateRoles(request.getRoles(), currentUserHighestAdminRole);
                    if (!youAreNotAllowedToAssignTheseRoles.isEmpty()) {
                        skipped.add(Map.of(
                                "request", request,
                                "message", "Skipping request as you are not allowed to assign these roles",
                                "you_are_not_allowed_to_assign_these_roles", youAreNotAllowedToAssignTheseRoles
                        ));
                        continue;
                    }
                    allRoles.addAll(request.getRoles());
                }
            } else request.setRoles(new HashSet<>());
            validRequests.add(request);
        }
        if (validRequests.isEmpty()) {
            var response = new LinkedHashMap<>();
            response.put("requested", requests.size());
            response.put("created", 0);
            response.put("skipped", requests.size());
            if (!skipped.isEmpty()) response.put("skipped_details", skipped);
            return response;
        }
        var existingUsersByUsername = userModelRepo.findByUsernameIn(usernames);
        var existingUsersByEmail = userModelRepo.findByEmailIn(emails);
        var existingUsernames = existingUsersByUsername.stream()
                .map(UserModel::getUsername)
                .collect(Collectors.toSet());
        var existingEmails = existingUsersByEmail.stream()
                .map(UserModel::getEmail)
                .map(String::toLowerCase)
                .collect(Collectors.toSet());
        validRequests = validRequests.stream()
                .filter(request -> {
                    if (existingUsernames.contains(request.getUsername())) {
                        skipped.add(Map.of(
                                "request", request,
                                "message", "Skipping request as user with same username already exists",
                                "existing_username", request.getUsername()
                        ));
                        return false;
                    }
                    if (existingEmails.contains(request.getEmail().toLowerCase())) {
                        skipped.add(Map.of(
                                "request", request,
                                "message", "Skipping request as user with same email already exists",
                                "existing_email", request.getEmail()
                        ));
                        return false;
                    }
                    return true;
                })
                .collect(Collectors.toSet());
        if (validRequests.isEmpty()) {
            var response = new LinkedHashMap<>();
            response.put("requested", requests.size());
            response.put("created", 0);
            response.put("skipped", requests.size());
            if (!skipped.isEmpty()) response.put("skipped_details", skipped);
            return response;
        }
        var resolvedRoles = roleModelRepo.findAllById((allRoles));
        var rolesMap = resolvedRoles.stream().collect(Collectors.toMap(RoleModel::getRoleName, Function.identity()));
        var newUsers = new HashSet<UserModel>();
        var currentAuthenticatedUser = CurrentUserUtil.getCurrentAuthenticatedUser();
        for (var request : validRequests) {
            if (request.getRoles().isEmpty())
                newUsers.add(toUserModel(request, new HashSet<>(), currentAuthenticatedUser));
            else {
                var missingRoles = request.getRoles().stream().filter(role -> !rolesMap.containsKey(role)).collect(Collectors.toSet());
                if (missingRoles.isEmpty()) {
                    newUsers.add(toUserModel(request,
                            request.getRoles().stream()
                                    .map(rolesMap::get)
                                    .filter(Objects::nonNull)
                                    .collect(Collectors.toSet()),
                            currentAuthenticatedUser));
                } else skipped.add(Map.of(
                        "request", request,
                        "message", "Skipping request as it has non-existing roles",
                        "non_existing_roles", missingRoles
                ));
            }
        }
        var response = new LinkedHashMap<>();
        if (!newUsers.isEmpty()) {
            var savedUsers = userModelRepo.saveAll(newUsers);
            response.put("users", savedUsers.stream()
                    .map(UserMapperUtil::toSummaryDto)
                    .toList());
            response.put("requested", requests.size());
            response.put("created", savedUsers.size());
            response.put("skipped", requests.size() - savedUsers.size());
        } else {
            response.put("requested", requests.size());
            response.put("created", 0);
            response.put("skipped", requests.size());
        }
        if (!skipped.isEmpty()) response.put("skipped_details", skipped);
        return response;
    }

    public Map<Object, Object> deleteUsersLenient(Set<String> usernamesOrEmails) {
        var usernames = new HashSet<String>();
        var emails = new HashSet<String>();
        var skipped = new HashSet<>();
        for (var identifier : usernamesOrEmails) {
            if (ValidationsUtil.EMAIL_PATTERN.matcher(identifier).matches()) emails.add(identifier);
            else if (ValidationsUtil.USERNAME_PATTERN.matcher(identifier).matches()) usernames.add(identifier);
            else skipped.add(Map.of(
                        "request", identifier,
                        "message", "Skipping request as no user found with this username/email"
                ));
        }
        var currentAuthenticatedUser = CurrentUserUtil.getCurrentAuthenticatedUser();
        if (usernames.remove(currentAuthenticatedUser.getUsername())) skipped.add(Map.of(
                "request", currentAuthenticatedUser.getUsername(),
                "message", "Skipping request with as you cannot delete your own account using this endpoint"
        ));
        if (emails.remove(currentAuthenticatedUser.getEmail())) skipped.add(Map.of(
                "request", currentAuthenticatedUser.getEmail(),
                "message", "Skipping request with as you cannot delete your own account using this endpoint"
        ));
        var usersByUsername = userModelRepo.findByUsernameIn(usernames);
        var usersByEmail = userModelRepo.findByEmailIn(emails);
        var foundUsernames = usersByUsername.stream().map(UserModel::getUsername).collect(Collectors.toSet());
        var foundEmails = usersByEmail.stream().map(UserModel::getEmail).map(String::toLowerCase).collect(Collectors.toSet());
        usernames.removeAll(foundUsernames);
        emails.removeAll(foundEmails);
        usernames.forEach(username -> skipped.add(Map.of(
                "request", username,
                "message", "Skipping request as no user found with this username"
        )));
        emails.forEach(email -> skipped.add(Map.of(
                "request", email,
                "message", "Skipping request as no user found with this email"
        )));
        var currentUserHighestAdminRole = CurrentUserUtil.getCurrentAuthenticatedUserHighestAdminRole();
        var usersToDelete = new HashSet<UserModel>();
        usersByUsername.forEach(user -> {
            var youCannotDeleteUserWithTheseRoles = validateRoles(user, currentUserHighestAdminRole);
            if (!youCannotDeleteUserWithTheseRoles.isEmpty()) {
                skipped.add(Map.of(
                        "request", user.getUsername(),
                        "message", "Skipping request as you are not allowed to delete user with these roles",
                        "you_are_not_allowed_to_delete_user_with_these_roles", youCannotDeleteUserWithTheseRoles
                ));
                return;
            }
            usersToDelete.add(user);
        });
        usersByEmail.forEach(user -> {
            var youCannotDeleteUserWithTheseRoles = validateRoles(user, currentUserHighestAdminRole);
            if (!youCannotDeleteUserWithTheseRoles.isEmpty()) {
                skipped.add(Map.of(
                        "request", user.getEmail(),
                        "message", "Skipping request as you are not allowed to delete user with these roles",
                        "you_are_not_allowed_to_delete_user_with_these_roles", youCannotDeleteUserWithTheseRoles
                ));
                return;
            }
            usersToDelete.add(user);
        });
        var response = new LinkedHashMap<>();
        response.put("requested", usernamesOrEmails.size());
        if (!usersToDelete.isEmpty()) {
            jwtUtil.revokeAccessTokens(usersToDelete);
            jwtUtil.revokeRefreshTokensByUsers(usersToDelete);
            userModelRepo.deleteAll(usersToDelete);
        }
        response.put("deleted", usersToDelete.size());
        response.put("skipped", usernamesOrEmails.size() - usersToDelete.size());
        if (!skipped.isEmpty()) response.put("skipped_details", skipped);
        return response;
    }

    public Map<Object, Object> getUsersLenient(Set<String> usernamesOrEmails) {
        var usernames = new HashSet<String>();
        var emails = new HashSet<String>();
        var skipped = new HashSet<>();
        for (var identifier : usernamesOrEmails) {
            if (ValidationsUtil.EMAIL_PATTERN.matcher(identifier).matches()) emails.add(identifier);
            else if (ValidationsUtil.USERNAME_PATTERN.matcher(identifier).matches()) usernames.add(identifier);
            else skipped.add(Map.of(
                        "request", identifier,
                        "message", "Skipping request as no user found with this username/email"
                ));
        }
        var usersByUsername = userModelRepo.findByUsernameIn(usernames);
        var usersByEmail = userModelRepo.findByEmailIn(emails);
        var foundUsernames = usersByUsername.stream().map(UserModel::getUsername).collect(Collectors.toSet());
        var foundEmails = usersByEmail.stream().map(UserModel::getEmail).map(String::toLowerCase).collect(Collectors.toSet());
        usernames.removeAll(foundUsernames);
        emails.removeAll(foundEmails);
        usernames.forEach(username -> skipped.add(Map.of(
                "request", username,
                "message", "Skipping request as no user found with this username"
        )));
        emails.forEach(email -> skipped.add(Map.of(
                "request", email,
                "message", "Skipping request as no user found with this email"
        )));
        if (!usersByEmail.isEmpty()) usersByUsername.addAll(usersByEmail);
        var response = new LinkedHashMap<>();
        if (!usersByUsername.isEmpty())
            response.put("users", usersByUsername.stream().map(UserMapperUtil::toSummaryDto).toList());
        response.put("requested", usernamesOrEmails.size());
        response.put("returned", usersByUsername.size());
        response.put("skipped", usernamesOrEmails.size() - usersByUsername.size());
        if (!skipped.isEmpty()) response.put("skipped_details", skipped);
        return response;
    }

    public Map<Object, Object> updateUsersLenient(Set<UserUpdationDto> requests) {
        Set<UserUpdationDto> validRequests = new HashSet<>();
        var usernames = new HashSet<String>();
        var emails = new HashSet<String>();
        var skipped = new HashSet<>();
        var roleNames = new HashSet<String>();
        var currentUserHighestAdminRole = CurrentUserUtil.getCurrentAuthenticatedUserHighestAdminRole();
        for (var request : requests) {
            try {
                ValidationsUtil.validateUsername(request.getUsername());
                if (!usernames.add(request.getUsername())) {
                    skipped.add(Map.of(
                            "request", request,
                            "message", "Skipping request as same username found in previous requests",
                            "same_username_in_previous_requests", request.getUsername()
                    ));
                    continue;
                }
            } catch (BadRequestExc e) {
                skipped.add(Map.of(
                        "request", request,
                        "message", "Skipping request as no user found with this username",
                        "username_not_found", request.getUsername()
                ));
                continue;
            }
            try {
                if (request.getEmail() != null) {
                    ValidationsUtil.validateEmail(request.getEmail());
                    if (!emails.add(request.getEmail())) {
                        skipped.add(Map.of(
                                "request", request,
                                "message", "Skipping request as same email found in previous requests",
                                "same_email_in_previous_requests", request.getEmail()
                        ));
                        continue;
                    }
                }
            } catch (BadRequestExc e) {
                skipped.add(Map.of(
                        "request", request,
                        "message", "Skipping request as it has invalid email",
                        "invalid_email", request.getEmail()
                ));
                continue;
            }
            if (request.getRoles() != null && !request.getRoles().isEmpty()) {
                request.setRoles(request.getRoles().stream().filter(r -> r != null && !r.isBlank()).collect(Collectors.toSet()));
                if (!request.getRoles().isEmpty()) {
                    var youAreNotAllowedToAssignTheseRoles = validateRoles(request.getRoles(), currentUserHighestAdminRole);
                    if (!youAreNotAllowedToAssignTheseRoles.isEmpty()) {
                        skipped.add(Map.of(
                                "request", request,
                                "message", "Skipping request as you are not allowed to assign these roles",
                                "you_are_not_allowed_to_assign_these_roles", youAreNotAllowedToAssignTheseRoles
                        ));
                        continue;
                    }
                    roleNames.addAll(request.getRoles());
                }
            }
            validRequests.add(request);
        }
        if (validRequests.isEmpty()) {
            var response = new LinkedHashMap<>();
            response.put("requested", requests.size());
            response.put("updated", 0);
            response.put("skipped", requests.size());
            if (!skipped.isEmpty()) response.put("skipped_details", skipped);
            return response;
        }
        var existingUsersByUsername = userModelRepo.findByUsernameIn(usernames);
        var existingUsersByEmail = userModelRepo.findByEmailIn(emails);
        var requestedEmailToUsername = validRequests.stream()
                .filter(r -> r.getEmail() != null)
                .collect(Collectors.toMap(
                        r -> r.getEmail().toLowerCase(),
                        UserUpdationDto::getUsername,
                        (u1, u2) -> u1
                ));
        var conflictingEmails = existingUsersByEmail.stream()
                .filter(user -> {
                    var requesterForThisEmail = requestedEmailToUsername.get(user.getEmail().toLowerCase());
                    return requesterForThisEmail != null && !user.getUsername().equals(requesterForThisEmail);
                })
                .map(UserModel::getEmail)
                .collect(Collectors.toSet());
        validRequests = validRequests.stream()
                .filter(request -> {
                    if (request.getEmail() == null) return true;
                    else if (!conflictingEmails.contains(request.getEmail().toLowerCase())) return true;
                    skipped.add(Map.of(
                            "request", request,
                            "message", "Skipping request as user with same email already exists",
                            "existing_email", request.getEmail()
                    ));
                    return false;
                })
                .collect(Collectors.toSet());
        var existingUsersByUsernameMap = existingUsersByUsername.stream().collect(Collectors.toMap(UserModel::getUsername, Function.identity()));
        var existingRolesMap = roleModelRepo.findAllById(roleNames).stream().collect(Collectors.toMap(RoleModel::getRoleName, Function.identity()));
        var updatedUsers = new HashSet<UserModel>();
        var usersToWhichWeHaveToRevokeTokens = new HashSet<UserModel>();
        var currentUser = CurrentUserUtil.getCurrentAuthenticatedUser();
        for (var request : validRequests) {
            var userToUpdate = existingUsersByUsernameMap.get(request.getUsername());
            if (userToUpdate == null) {
                skipped.add(Map.of(
                        "request", request,
                        "message", "Skipping request as no user found with this username",
                        "username_not_found", request.getUsername()
                ));
                continue;
            }
            if (currentUser.getUsername().equals(request.getUsername())) {
                skipped.add(Map.of(
                        "request", request,
                        "message", "Skipping request as you cannot modify your own account using this endpoint",
                        "cannot_modify_your_own_account", request.getUsername()
                ));
                continue;
            }
            var youCannotModifyUserWithTheseRoles = validateRoles(userToUpdate, currentUserHighestAdminRole);
            if (!youCannotModifyUserWithTheseRoles.isEmpty()) {
                skipped.add(Map.of(
                        "request", request,
                        "message", "Skipping request as you are not allowed to modify user with these roles",
                        "you_are_not_allowed_to_modify_user_with_these_roles", youCannotModifyUserWithTheseRoles
                ));
                continue;
            }
            var userModificationDto = validateAndSetUserDetailsBasic(userToUpdate, request);
            if (!userModificationDto.getInvalidInputs().isEmpty()) {
                skipped.add(Map.of(
                        "request", request,
                        "message", "Skipping request as it has invalid inputs",
                        "invalid_inputs", userModificationDto.getInvalidInputs()
                ));
                continue;
            }
            if (request.getEmail() != null && !request.getEmail().equals(userToUpdate.getEmail())) {
                userToUpdate.setEmail(request.getEmail());
                userToUpdate.setRealEmail(request.getEmail());
                userModificationDto.setModified(true);
                userModificationDto.setShouldRemoveTokens(true);
            }
            if (request.getRoles() != null) {
                var missingRoles = request.getRoles().stream().filter(role -> !existingRolesMap.containsKey(role)).collect(Collectors.toSet());
                if (!missingRoles.isEmpty()) {
                    skipped.add(Map.of(
                            "request", request,
                            "message", "Skipping request as it has roles that do not exist",
                            "non_existing_roles", missingRoles
                    ));
                    continue;
                }
                var rolesToAssign = request.getRoles().stream().map(existingRolesMap::get).filter(Objects::nonNull).collect(Collectors.toSet());
                if (!userToUpdate.getRoles().equals(rolesToAssign)) {
                    userToUpdate.setRoles(rolesToAssign);
                    userModificationDto.setModified(true);
                    userModificationDto.setShouldRemoveTokens(true);
                }
            }
            if (userModificationDto.isModified()) {
                userToUpdate.setUpdatedBy(currentUser.getUsername());
                if (userModificationDto.isShouldRemoveTokens()) {
                    usersToWhichWeHaveToRevokeTokens.add(userToUpdate);
                } else updatedUsers.add(userToUpdate);
            }
        }
        if (usersToWhichWeHaveToRevokeTokens.isEmpty() && updatedUsers.isEmpty()) {
            var response = new LinkedHashMap<>();
            response.put("requested", requests.size());
            response.put("updated", 0);
            response.put("skipped", requests.size());
            if (!skipped.isEmpty()) response.put("skipped_details", skipped);
            return response;
        }
        if (!usersToWhichWeHaveToRevokeTokens.isEmpty()) {
            jwtUtil.revokeAccessTokens(usersToWhichWeHaveToRevokeTokens);
            jwtUtil.revokeRefreshTokensByUsers(usersToWhichWeHaveToRevokeTokens);
            updatedUsers.addAll(usersToWhichWeHaveToRevokeTokens);
        }
        var updatedUsersInDb = userModelRepo.saveAll(updatedUsers);
        var response = new LinkedHashMap<>();
        response.put("users", updatedUsersInDb.stream()
                .map(UserMapperUtil::toSummaryDto)
                .toList());
        response.put("requested", requests.size());
        response.put("updated", updatedUsersInDb.size());
        response.put("skipped", requests.size() - updatedUsersInDb.size());
        if (!skipped.isEmpty()) response.put("skipped_details", skipped);
        return response;
    }

    public Map<Object, Object> createRolesLenient(Set<RoleCreationDto> roles) {
        Set<RoleCreationDto> validRequests = new HashSet<>();
        var roleNames = new HashSet<String>();
        var skipped = new HashSet<>();
        var permissionNames = new HashSet<String>();
        for (var role : roles) {
            var invalidInputs = InputValidationUtil.validateInputs(role);
            if (!invalidInputs.isEmpty()) {
                skipped.add(Map.of(
                        "request", role,
                        "message", "Skipping request as it has invalid inputs",
                        "invalid_inputs", invalidInputs
                ));
                continue;
            }
            if (!roleNames.add(role.getRoleName())) {
                skipped.add(Map.of(
                        "request", role,
                        "message", "Skipping request as same role name found in previous requests",
                        "same_role_name_in_previous_requests", role.getRoleName()
                ));
                continue;
            }
            if (role.getPermissions() != null && !role.getPermissions().isEmpty()) {
                role.setPermissions(role.getPermissions().stream().filter(p -> p != null && !p.isBlank()).collect(Collectors.toSet()));
                if (!role.getPermissions().isEmpty()) permissionNames.addAll(role.getPermissions());
            } else role.setPermissions(new HashSet<>());
            validRequests.add(role);
        }
        if (validRequests.isEmpty()) {
            var response = new LinkedHashMap<>();
            response.put("requested", roles.size());
            response.put("created", 0);
            response.put("skipped", roles.size());
            if (!skipped.isEmpty()) response.put("skipped_details", skipped);
            return response;
        }
        var existingRoles = roleModelRepo.findAllById(roleNames);
        var existingRoleNames = existingRoles.stream().map(RoleModel::getRoleName).collect(Collectors.toSet());
        validRequests = validRequests.stream()
                .filter(role -> {
                    if (!existingRoleNames.contains(role.getRoleName())) return true;
                    skipped.add(Map.of(
                            "request", role,
                            "message", "Skipping request due to existing role with same name",
                            "existing_role_with_role_name", role.getRoleName()
                    ));
                    return false;
                })
                .collect(Collectors.toSet());
        if (validRequests.isEmpty()) {
            var response = new LinkedHashMap<>();
            response.put("requested", roles.size());
            response.put("created", 0);
            response.put("skipped", roles.size());
            if (!skipped.isEmpty()) response.put("skipped_details", skipped);
            return response;
        }
        var permissionsMap = permissionModelRepo.findAllById(permissionNames).stream().collect(Collectors.toMap(PermissionModel::getPermissionName, Function.identity()));
        var newRoles = new HashSet<RoleModel>();
        var currentUser = CurrentUserUtil.getCurrentAuthenticatedUser();
        for (var role : validRequests) {
            if (role.getPermissions().isEmpty()) newRoles.add(toRoleModel(role, new HashSet<>(), currentUser));
            else {
                var missingPermissions = role.getPermissions().stream().filter(p -> !permissionsMap.containsKey(p)).collect(Collectors.toSet());
                if (missingPermissions.isEmpty()) {
                    newRoles.add(toRoleModel(role,
                            role.getPermissions().stream().map(permissionsMap::get)
                                    .filter(Objects::nonNull)
                                    .collect(Collectors.toSet()),
                            currentUser));
                } else skipped.add(Map.of(
                        "request", role,
                        "message", "Skipping request as it has permissions that do not exist",
                        "non_existing_permissions", missingPermissions
                ));
            }
        }
        if (newRoles.isEmpty()) {
            var response = new LinkedHashMap<>();
            response.put("requested", roles.size());
            response.put("created", 0);
            response.put("skipped", roles.size());
            response.put("skipped_details", skipped);
            return response;
        }
        var created = roleModelRepo.saveAll(newRoles);
        var response = new LinkedHashMap<>();
        response.put("roles", created.stream()
                .map(RoleMapperUtil::toSummaryDto)
                .collect(Collectors.toSet()));
        response.put("requested", roles.size());
        response.put("created", created.size());
        response.put("skipped", roles.size() - created.size());
        if (!skipped.isEmpty()) response.put("skipped_details", skipped);
        return response;
    }

    public Map<Object, Object> deleteRolesLenient(Set<String> roleNames) {
        var skipped = new HashSet<>();
        roleNames = roleNames.stream().filter(rolename -> {
            try {
                ValidationsUtil.validateRoleName(rolename);
                return true;
            } catch (BadRequestExc e) {
                skipped.add(Map.of(
                        "request", rolename,
                        "message", "Skipping request as no role found with this name"
                ));
                return false;
            }
        }).collect(Collectors.toSet());
        var foundRoles = roleModelRepo.findAllById(roleNames);
        var foundRoleNames = foundRoles.stream().map(RoleModel::getRoleName).collect(Collectors.toSet());
        roleNames.removeAll(foundRoleNames);
        roleNames.forEach(roleName -> skipped.add(Map.of(
                "request", roleName,
                "message", "Skipping request as no role found with this name"
        )));
        var rolesToDelete = new HashSet<RoleModel>();
        for (var role : foundRoles) {
            if (role.isSystemRole()) {
                skipped.add(Map.of(
                        "request", role.getRoleName(),
                        "message", "Skipping request as you cannot delete a system role"
                ));
                continue;
            }
            var count = userModelRepo.countByRoles_RoleName(role.getRoleName());
            if (count > 0) {
                skipped.add(Map.of(
                        "request", role.getRoleName(),
                        "message", "Skipping request as there are users with this role assigned",
                        "number_of_users_with_this_role", count
                ));
                continue;
            }
            rolesToDelete.add(role);
        }
        if (rolesToDelete.isEmpty()) {
            var response = new LinkedHashMap<>();
            response.put("requested", roleNames.size());
            response.put("deleted", 0);
            response.put("skipped", roleNames.size());
            if (!skipped.isEmpty()) response.put("skipped_details", skipped);
            return response;
        }
        roleModelRepo.deleteAll(rolesToDelete);
        var response = new LinkedHashMap<>();
        response.put("requested", roleNames.size());
        response.put("deleted", rolesToDelete.size());
        response.put("skipped", roleNames.size() - rolesToDelete.size());
        if (!skipped.isEmpty()) response.put("skipped_details", skipped);
        return response;
    }

    public Map<Object, Object> getRolesLenient(Set<String> roleNames) {
        var skipped = new HashSet<>();
        roleNames = roleNames.stream().filter(rolename -> {
            try {
                ValidationsUtil.validateRoleName(rolename);
                return true;
            } catch (BadRequestExc e) {
                skipped.add(Map.of(
                        "request", rolename,
                        "message", "Skipping request as no role found with this name"
                ));
                return false;
            }
        }).collect(Collectors.toSet());
        var foundRoles = roleModelRepo.findAllById(roleNames);
        var foundRoleNames = foundRoles.stream().map(RoleModel::getRoleName).collect(Collectors.toSet());
        roleNames.removeAll(foundRoleNames);
        roleNames.forEach(roleName -> skipped.add(Map.of(
                "request", roleName,
                "message", "Skipping request as no role found with this name"
        )));
        var response = new LinkedHashMap<>();
        if (!foundRoles.isEmpty()) {
            response.put("roles", foundRoles.stream()
                    .map(RoleMapperUtil::toSummaryDto)
                    .collect(Collectors.toSet()));
        }
        response.put("requested", roleNames.size());
        response.put("returned", foundRoles.size());
        response.put("skipped", roleNames.size() - foundRoles.size());
        if (!skipped.isEmpty()) response.put("skipped_details", skipped);
        return response;
    }

    public Map<Object, Object> updateRolesLenient(Set<RoleCreationDto> roles) {
        Set<RoleCreationDto> validRequests = new HashSet<>();
        var roleNames = new HashSet<String>();
        var skipped = new HashSet<>();
        var permissionNames = new HashSet<String>();
        for (var role : roles) {
            try {
                ValidationsUtil.validateRoleName(role.getRoleName());
                if (!roleNames.add(role.getRoleName())) {
                    skipped.add(Map.of(
                            "request", role,
                            "message", "Skipping request as same role name found in previous requests",
                            "same_role_name_in_previous_requests", role.getRoleName()
                    ));
                    continue;
                }
            } catch (BadRequestExc e) {
                skipped.add(Map.of(
                        "request", role,
                        "message", "Skipping request as no role found with this name",
                        "no_role_found_with_name", role.getRoleName()
                ));
                continue;
            }
            if (role.getPermissions() != null && !role.getPermissions().isEmpty()) {
                role.setPermissions(role.getPermissions().stream().filter(p -> p != null && !p.isBlank()).collect(Collectors.toSet()));
                if (!role.getPermissions().isEmpty()) permissionNames.addAll(role.getPermissions());
            }
            validRequests.add(role);
        }
        if (validRequests.isEmpty()) {
            var response = new LinkedHashMap<>();
            response.put("requested", roles.size());
            response.put("updated", 0);
            response.put("skipped", roles.size());
            if (!skipped.isEmpty()) response.put("skipped_details", skipped);
            return response;
        }
        var existingRolesMap = roleModelRepo.findAllById(roleNames).stream().collect(Collectors.toMap(RoleModel::getRoleName, Function.identity()));
        var permissionsMap = permissionModelRepo.findAllById(permissionNames).stream().collect(Collectors.toMap(PermissionModel::getPermissionName, Function.identity()));
        var updatedRoles = new HashSet<RoleModel>();
        var rolesForWhichWeHaveToRevokeTokensOfUsersWhoHaveTheseRoles = new HashSet<RoleModel>();
        var currentAuthenticatedUser = CurrentUserUtil.getCurrentAuthenticatedUser();
        validRequests.forEach(role -> {
            var roleToUpdate = existingRolesMap.get(role.getRoleName());
            if (roleToUpdate == null) {
                skipped.add(Map.of(
                        "request", role,
                        "message", "Skipping request as no role found with this name",
                        "no_role_found_with_name", role.getRoleName()
                ));
                return;
            }
            var roleModificationDto = validateAndSetRoleDetails(roleToUpdate, role);
            if (role.getPermissions() != null) {
                var missingPermissions = role.getPermissions().stream().filter(p -> !permissionsMap.containsKey(p)).collect(Collectors.toSet());
                if (missingPermissions.isEmpty()) {
                    var permissionsToAssign = role.getPermissions().stream()
                            .map(permissionsMap::get)
                            .filter(Objects::nonNull)
                            .collect(Collectors.toSet());
                    if (!roleToUpdate.getPermissions().equals(permissionsToAssign)) {
                        roleToUpdate.setPermissions(permissionsToAssign);
                        roleModificationDto.setModified(true);
                        roleModificationDto.setShouldRemoveTokensOfUsersHavingThisRole(true);
                    }
                } else {
                    skipped.add(Map.of(
                            "request", role,
                            "message", "Skipping request as it has permissions that do not exist",
                            "non_existing_permissions", missingPermissions
                    ));
                    return;
                }
            }
            if (roleModificationDto.isModified()) {
                roleToUpdate.setUpdatedBy(currentAuthenticatedUser.getUsername());
                if (roleModificationDto.isShouldRemoveTokensOfUsersHavingThisRole())
                    rolesForWhichWeHaveToRevokeTokensOfUsersWhoHaveTheseRoles.add(roleToUpdate);
                else updatedRoles.add(roleToUpdate);
            }
        });
        if (updatedRoles.isEmpty() && rolesForWhichWeHaveToRevokeTokensOfUsersWhoHaveTheseRoles.isEmpty()) {
            var response = new LinkedHashMap<>();
            response.put("requested", roles.size());
            response.put("updated", 0);
            response.put("skipped", roles.size());
            if (!skipped.isEmpty()) response.put("skipped_details", skipped);
            return response;
        }
        if (!rolesForWhichWeHaveToRevokeTokensOfUsersWhoHaveTheseRoles.isEmpty()) {
            var users = userModelRepo.findByRolesIn(rolesForWhichWeHaveToRevokeTokensOfUsersWhoHaveTheseRoles);
            if (!users.isEmpty()) {
                jwtUtil.revokeAccessTokens(users);
                jwtUtil.revokeRefreshTokensByUsers(users);
            }
            updatedRoles.addAll(rolesForWhichWeHaveToRevokeTokensOfUsersWhoHaveTheseRoles);
        }
        var updatedRolesInDb = roleModelRepo.saveAll(updatedRoles);
        var response = new LinkedHashMap<>();
        response.put("roles", updatedRolesInDb.stream()
                .map(RoleMapperUtil::toSummaryDto)
                .collect(Collectors.toSet()));
        response.put("requested", roles.size());
        response.put("updated", updatedRolesInDb.size());
        response.put("skipped", roles.size() - updatedRolesInDb.size());
        if (!skipped.isEmpty()) response.put("skipped_details", skipped);
        return response;
    }

    public Map<Object, Object> getPermissionsLenient(Set<String> permissionNames) {
        var skipped = new HashSet<>();
        permissionNames = permissionNames.stream().filter(permissionName -> {
            try {
                ValidationsUtil.validatePermissionName(permissionName);
                return true;
            } catch (BadRequestExc e) {
                skipped.add(Map.of(
                        "request", permissionName,
                        "message", "Skipping request as no permission found with this name"
                ));
                return false;
            }
        }).collect(Collectors.toSet());
        var foundPermissions = permissionModelRepo.findAllById(permissionNames);
        var foundPermissionNames = foundPermissions.stream().map(PermissionModel::getPermissionName).collect(Collectors.toSet());
        permissionNames.removeAll(foundPermissionNames);
        permissionNames.forEach(permissionName -> skipped.add(Map.of(
                "request", permissionName,
                "message", "Skipping request as no permission found with this name"
        )));
        var response = new LinkedHashMap<>();
        if (foundPermissions.isEmpty()) {
            response.put("permissions", foundPermissions);
        }
        response.put("requested", permissionNames.size());
        response.put("returned", foundPermissions.size());
        response.put("skipped", permissionNames.size() - foundPermissions.size());
        if (!skipped.isEmpty()) response.put("skipped_details", skipped);
        return response;
    }
}