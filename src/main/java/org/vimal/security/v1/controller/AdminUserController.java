package org.vimal.security.v1.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.vimal.security.v1.dto.RoleCreationDto;
import org.vimal.security.v1.dto.UserCreationDto;
import org.vimal.security.v1.dto.UserUpdationDto;
import org.vimal.security.v1.exception.BadRequestExc;
import org.vimal.security.v1.service.AdminUserService;

import java.util.Set;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/user/admin")
public class AdminUserController {
    private final AdminUserService adminUserService;

    @PostMapping("/create-user")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canCreateUsers()")
    public ResponseEntity<?> createUser(@RequestBody UserCreationDto request) {
        return adminUserService.createUser(request);
    }

    @PostMapping("/create-users")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canCreateUsers()")
    public ResponseEntity<?> createUsers(@RequestBody Set<UserCreationDto> request) {
        if (request.isEmpty()) throw new BadRequestExc("No valid requests provided");
        else if (request.size() > 100) throw new BadRequestExc("Cannot create more than 100 users at a time");
        return adminUserService.createUsers(request);
    }

    @DeleteMapping("/delete-user-by-username")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canDeleteUsers()")
    public ResponseEntity<?> deleteUserByUsername(@RequestParam String username) {
        return adminUserService.deleteUserByUsername(username);
    }

    @DeleteMapping("/delete-user-by-email")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canDeleteUsers()")
    public ResponseEntity<?> deleteUserByEmail(@RequestParam String email) {
        return adminUserService.deleteUserByEmail(email);
    }

    @DeleteMapping("/delete-user")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canDeleteUsers()")
    public ResponseEntity<?> deleteUser(@RequestParam String usernameOrEmail) {
        return adminUserService.deleteUser(usernameOrEmail);
    }

    @DeleteMapping("/delete-users")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canDeleteUsers()")
    public ResponseEntity<?> deleteUsers(@RequestBody Set<String> usernamesOrEmails) {
        if (usernamesOrEmails.isEmpty()) throw new BadRequestExc("No valid usernames or emails provided");
        else if (usernamesOrEmails.size() > 100) throw new BadRequestExc("Cannot delete more than 100 users at a time");
        return adminUserService.deleteUsers(usernamesOrEmails);
    }

    @GetMapping("/get-user-by-username")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canReadUsers()")
    public ResponseEntity<?> getUserByUsername(@RequestParam String username) {
        return ResponseEntity.ok(adminUserService.getUserByUsername(username));
    }

    @GetMapping("/get-user-by-email")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canReadUsers()")
    public ResponseEntity<?> getUserByEmail(@RequestParam String email) {
        return ResponseEntity.ok(adminUserService.getUserByEmail(email));
    }

    @GetMapping("/get-user")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canReadUsers()")
    public ResponseEntity<?> getUser(@RequestParam String usernameOrEmail) {
        return adminUserService.getUser(usernameOrEmail);
    }

    @GetMapping("/get-users")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canReadUsers()")
    public ResponseEntity<?> getUsers(@RequestBody Set<String> usernamesOrEmails) {
        if (usernamesOrEmails.isEmpty()) throw new BadRequestExc("No valid usernames or emails provided");
        else if (usernamesOrEmails.size() > 100) throw new BadRequestExc("Cannot get more than 100 users at a time");
        return adminUserService.getUsers(usernamesOrEmails);
    }

    @PutMapping("/update-user")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canUpdateUsers()")
    public ResponseEntity<?> updateUser(@RequestParam String usernameOrEmail,
                                        @RequestBody UserUpdationDto request) {
        return adminUserService.updateUser(usernameOrEmail, request);
    }

    @PutMapping("/update-users")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canUpdateUsers()")
    public ResponseEntity<?> updateUsers(@RequestBody Set<UserUpdationDto> request) {
        if (request.isEmpty()) throw new BadRequestExc("No valid requests provided");
        else if (request.size() > 100) throw new BadRequestExc("Cannot update more than 100 users at a time");
        return adminUserService.updateUsers(request);
    }

    @GetMapping("/get-permission")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canReadPermissions()")
    public ResponseEntity<?> getPermission(@RequestParam String permissionName) {
        return ResponseEntity.ok(adminUserService.getPermission(permissionName));
    }

    @GetMapping("/get-permissions")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canReadPermissions()")
    public ResponseEntity<?> getPermissions(@RequestBody Set<String> permissionNames) {
        if (permissionNames.isEmpty()) throw new BadRequestExc("No valid permission names provided");
        else if (permissionNames.size() > 100)
            throw new BadRequestExc("Cannot get more than 100 permissions at a time");
        return adminUserService.getPermissions(permissionNames);
    }

    @PostMapping("/create-role")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canCreateRoles()")
    public ResponseEntity<?> createRole(@RequestBody RoleCreationDto role) {
        return adminUserService.createRole(role);
    }

    @PostMapping("/create-roles")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canCreateRoles()")
    public ResponseEntity<?> createRoles(@RequestBody Set<RoleCreationDto> roles) {
        if (roles.isEmpty()) throw new BadRequestExc("No valid roles provided");
        else if (roles.size() > 100) throw new BadRequestExc("Cannot create more than 100 roles at a time");
        return adminUserService.createRoles(roles);
    }

    @DeleteMapping("/delete-role")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canDeleteRoles()")
    public ResponseEntity<?> deleteRole(@RequestParam String roleName) {
        return ResponseEntity.ok(adminUserService.deleteRole(roleName));
    }

    @DeleteMapping("/delete-roles")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canDeleteRoles()")
    public ResponseEntity<?> deleteRoles(@RequestBody Set<String> roleNames) {
        if (roleNames.isEmpty()) throw new BadRequestExc("No valid role names provided");
        else if (roleNames.size() > 100) throw new BadRequestExc("Cannot delete more than 100 roles at a time");
        return adminUserService.deleteRoles(roleNames);
    }

    @GetMapping("/get-role")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canReadRoles()")
    public ResponseEntity<?> getRole(@RequestParam String roleName) {
        return ResponseEntity.ok(adminUserService.getRole(roleName));
    }

    @GetMapping("/get-roles")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canReadRoles()")
    public ResponseEntity<?> getRoles(@RequestBody Set<String> roleNames) {
        if (roleNames.isEmpty()) throw new BadRequestExc("No valid role names provided");
        else if (roleNames.size() > 100) throw new BadRequestExc("Cannot get more than 100 roles at a time");
        return adminUserService.getRoles(roleNames);
    }

    @PutMapping("/update-role")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canUpdateRoles()")
    public ResponseEntity<?> updateRole(@RequestBody RoleCreationDto role) {
        return adminUserService.updateRole(role);
    }

    @PutMapping("/update-roles")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canUpdateRoles()")
    public ResponseEntity<?> updateRoles(@RequestBody Set<RoleCreationDto> roles) {
        if (roles.isEmpty()) throw new BadRequestExc("No valid roles provided");
        else if (roles.size() > 100) throw new BadRequestExc("Cannot update more than 100 roles at a time");
        return adminUserService.updateRoles(roles);
    }

    @GetMapping("/get-all-users")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canReadUsers()")
    public ResponseEntity<?> getAllUsers(
            @PageableDefault(size = 20, sort = "firstName", direction = Sort.Direction.ASC)
            Pageable pageable) {
        if (pageable.getPageSize() > 100) {
            pageable = PageRequest.of(
                    pageable.getPageNumber(),
                    100,
                    pageable.getSort()
            );
        }
        return ResponseEntity.ok(adminUserService.getAllUsers(pageable));
    }

    @GetMapping("/get-all-permissions")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canReadPermissions()")
    public ResponseEntity<?> getAllPermissions(
            @PageableDefault(size = 20, sort = "permissionName", direction = Sort.Direction.ASC)
            Pageable pageable) {
        if (pageable.getPageSize() > 100) {
            pageable = PageRequest.of(
                    pageable.getPageNumber(),
                    100,
                    pageable.getSort()
            );
        }
        return ResponseEntity.ok(adminUserService.getAllPermissions(pageable));
    }

    @GetMapping("/get-all-roles")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canReadRoles()")
    public ResponseEntity<?> getAllRoles(
            @PageableDefault(size = 20, sort = "roleName", direction = Sort.Direction.ASC)
            Pageable pageable) {
        if (pageable.getPageSize() > 100) {
            pageable = PageRequest.of(
                    pageable.getPageNumber(),
                    100,
                    pageable.getSort()
            );
        }
        return ResponseEntity.ok(adminUserService.getAllRoles(pageable));
    }

    @PostMapping("/enable-email-mfa-for-user")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canUpdateUsers()")
    public ResponseEntity<?> enableEmailMfaForUser(@RequestParam String usernameOrEmail) {
        return adminUserService.enableEmailMfaForUser(usernameOrEmail);
    }

    @PostMapping("/disable-email-mfa-for-user")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canUpdateUsers()")
    public ResponseEntity<?> disableEmailMfaForUser(@RequestParam String usernameOrEmail) {
        return adminUserService.disableEmailMfaForUser(usernameOrEmail);
    }

    @PostMapping("/create-users-lenient")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canCreateUsers()")
    public ResponseEntity<?> createUsersLenient(@RequestBody Set<UserCreationDto> requests) {
        if (requests.isEmpty()) throw new BadRequestExc("No valid requests provided");
        else if (requests.size() > 100) throw new BadRequestExc("Cannot create more than 100 users at a time");
        return ResponseEntity.ok(adminUserService.createUsersLenient(requests));
    }

    @DeleteMapping("/delete-users-lenient")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canDeleteUsers()")
    public ResponseEntity<?> deleteUsersLenient(@RequestBody Set<String> usernamesOrEmails) {
        if (usernamesOrEmails.isEmpty()) throw new BadRequestExc("No valid usernames or emails provided");
        else if (usernamesOrEmails.size() > 100) throw new BadRequestExc("Cannot delete more than 100 users at a time");
        return ResponseEntity.ok(adminUserService.deleteUsersLenient(usernamesOrEmails));
    }

    @GetMapping("/get-users-lenient")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canReadUsers()")
    public ResponseEntity<?> getUsersLenient(@RequestBody Set<String> usernamesOrEmails) {
        if (usernamesOrEmails.isEmpty()) throw new BadRequestExc("No valid usernames or emails provided");
        else if (usernamesOrEmails.size() > 100) throw new BadRequestExc("Cannot get more than 100 users at a time");
        return ResponseEntity.ok(adminUserService.getUsersLenient(usernamesOrEmails));
    }

    @PutMapping("/update-users-lenient")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canUpdateUsers()")
    public ResponseEntity<?> updateUsersLenient(@RequestBody Set<UserUpdationDto> requests) {
        if (requests.isEmpty()) throw new BadRequestExc("No valid requests provided");
        else if (requests.size() > 100) throw new BadRequestExc("Cannot update more than 100 users at a time");
        return ResponseEntity.ok(adminUserService.updateUsersLenient(requests));
    }

    @PostMapping("/create-roles-lenient")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canCreateRoles()")
    public ResponseEntity<?> createRolesLenient(@RequestBody Set<RoleCreationDto> roles) {
        if (roles.isEmpty()) throw new BadRequestExc("No valid roles provided");
        else if (roles.size() > 100) throw new BadRequestExc("Cannot create more than 100 roles at a time");
        return ResponseEntity.ok(adminUserService.createRolesLenient(roles));
    }

    @DeleteMapping("/delete-roles-lenient")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canDeleteRoles()")
    public ResponseEntity<?> deleteRolesLenient(@RequestBody Set<String> roleNames) {
        if (roleNames.isEmpty()) throw new BadRequestExc("No valid role names provided");
        else if (roleNames.size() > 100) throw new BadRequestExc("Cannot delete more than 100 roles at a time");
        return ResponseEntity.ok(adminUserService.deleteRolesLenient(roleNames));
    }

    @GetMapping("/get-roles-lenient")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canReadRoles()")
    public ResponseEntity<?> getRolesLenient(@RequestBody Set<String> roleNames) {
        if (roleNames.isEmpty()) throw new BadRequestExc("No valid role names provided");
        else if (roleNames.size() > 100) throw new BadRequestExc("Cannot get more than 100 roles at a time");
        return ResponseEntity.ok(adminUserService.getRolesLenient(roleNames));
    }

    @PutMapping("/update-roles-lenient")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canUpdateRoles()")
    public ResponseEntity<?> updateRolesLenient(@RequestBody Set<RoleCreationDto> roles) {
        if (roles.isEmpty()) throw new BadRequestExc("No valid roles provided");
        else if (roles.size() > 100) throw new BadRequestExc("Cannot update more than 100 roles at a time");
        return ResponseEntity.ok(adminUserService.updateRolesLenient(roles));
    }

    @GetMapping("/get-permissions-lenient")
    @PreAuthorize("@authz.isAdminOrAbove() or @authz.canReadPermissions()")
    public ResponseEntity<?> getPermissionsLenient(@RequestBody Set<String> permissionNames) {
        if (permissionNames.isEmpty()) throw new BadRequestExc("No valid permission names provided");
        else if (permissionNames.size() > 100)
            throw new BadRequestExc("Cannot get more than 100 permissions at a time");
        return ResponseEntity.ok(adminUserService.getPermissionsLenient(permissionNames));
    }
}