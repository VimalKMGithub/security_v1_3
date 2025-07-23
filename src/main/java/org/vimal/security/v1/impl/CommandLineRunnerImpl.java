package org.vimal.security.v1.impl;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.vimal.security.v1.config.properties.DummyUsersConfig;
import org.vimal.security.v1.exception.BadRequestExc;
import org.vimal.security.v1.model.PermissionModel;
import org.vimal.security.v1.model.RoleModel;
import org.vimal.security.v1.model.UserModel;
import org.vimal.security.v1.model.enums.SystemPermission;
import org.vimal.security.v1.model.enums.SystemRole;
import org.vimal.security.v1.repo.PermissionModelRepo;
import org.vimal.security.v1.repo.RoleModelRepo;
import org.vimal.security.v1.repo.UserModelRepo;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Component
public class CommandLineRunnerImpl implements CommandLineRunner {
    private final DummyUsersConfig dummyUsersConfig;
    private final PermissionModelRepo permissionModelRepo;
    private final RoleModelRepo roleModelRepo;
    private final UserModelRepo userModelRepo;
    private final PasswordEncoder passwordEncoder;

    public CommandLineRunnerImpl(DummyUsersConfig dummyUsersConfig,
                                 PermissionModelRepo permissionModelRepo,
                                 RoleModelRepo roleModelRepo,
                                 UserModelRepo userModelRepo,
                                 PasswordEncoder passwordEncoder) {
        this.dummyUsersConfig = dummyUsersConfig;
        this.permissionModelRepo = permissionModelRepo;
        this.roleModelRepo = roleModelRepo;
        this.userModelRepo = userModelRepo;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void run(String... args) {
        log.info("Initializing system permissions, roles, and dummy users...");
        initializeSystemPermissionsIfAbsent();
        initializeSystemRolesIfAbsent();
        assignPermissionsToRoles();
        initializeDummyUsersIfAbsent();
        log.info("System permissions, roles, and dummy users initialized successfully.");
    }

    private void initializeSystemPermissionsIfAbsent() {
        var allPermissionNames = Arrays.stream(SystemPermission.values())
                .map(SystemPermission::name)
                .collect(Collectors.toSet());
        var existingPermissions = permissionModelRepo.findAllById(allPermissionNames)
                .stream().map(PermissionModel::getPermissionName).collect(Collectors.toSet());
        var missingPermissions = allPermissionNames.stream()
                .filter(name -> !existingPermissions.contains(name))
                .collect(Collectors.toSet());
        var newPermissionModels = missingPermissions.stream()
                .map(name -> {
                    var permissionEnum = SystemPermission.valueOf(name);
                    return PermissionModel.builder()
                            .permissionName(name)
                            .description(permissionEnum.getDescription())
                            .systemPermission(true)
                            .createdBy("system")
                            .updatedBy("system")
                            .build();
                })
                .collect(Collectors.toSet());
        permissionModelRepo.saveAll(newPermissionModels);
    }

    private void initializeSystemRolesIfAbsent() {
        var allRoleNames = Arrays.stream(SystemRole.values())
                .map(SystemRole::name)
                .collect(Collectors.toSet());
        var existingRoles = roleModelRepo.findAllById(allRoleNames)
                .stream().map(RoleModel::getRoleName).collect(Collectors.toSet());
        var missingRoles = allRoleNames.stream()
                .filter(name -> !existingRoles.contains(name))
                .collect(Collectors.toSet());
        var newRoles = missingRoles.stream()
                .map(name -> {
                    return RoleModel.builder()
                            .roleName(name)
                            .systemRole(true)
                            .createdBy("system")
                            .updatedBy("system")
                            .build();
                })
                .collect(Collectors.toSet());
        roleModelRepo.saveAll(newRoles);
    }

    private void assignPermissionsToRoles() {
        assignPermissionsToRole(SystemRole.ROLE_MANAGE_ROLES, Set.of(SystemPermission.CAN_CREATE_ROLE,
                SystemPermission.CAN_READ_ROLE,
                SystemPermission.CAN_UPDATE_ROLE,
                SystemPermission.CAN_DELETE_ROLE));
        assignPermissionsToRole(SystemRole.ROLE_MANAGE_USERS, Set.of(SystemPermission.CAN_CREATE_USER,
                SystemPermission.CAN_READ_USER,
                SystemPermission.CAN_UPDATE_USER,
                SystemPermission.CAN_DELETE_USER));
        assignPermissionsToRole(SystemRole.ROLE_MANAGE_PERMISSIONS, Set.of(SystemPermission.CAN_READ_PERMISSION));
    }

    private void assignPermissionsToRole(SystemRole role,
                                         Set<SystemPermission> permissions) {
        var roleModel = roleModelRepo.findById(role.name()).orElseThrow(() -> new BadRequestExc("Role not found: " + role.name()));
        var permissionModels = new HashSet<>(permissionModelRepo.findAllById(permissions.stream().map(SystemPermission::name).collect(Collectors.toSet())));
        roleModel.getPermissions().addAll(permissionModels);
        roleModel.setUpdatedBy("system");
        roleModelRepo.save(roleModel);
    }

    private void initializeDummyUsersIfAbsent() {
        createUserIfNotExists(
                dummyUsersConfig.getGodUserEmail(),
                dummyUsersConfig.getGodUserUsername(),
                "God",
                dummyUsersConfig.getGodUserPassword(),
                Set.of(SystemRole.ROLE_GOD.name())
        );
        createUserIfNotExists(
                dummyUsersConfig.getGlobalAdminUserEmail(),
                dummyUsersConfig.getGlobalAdminUserUsername(),
                "Global Admin",
                dummyUsersConfig.getGlobalAdminUserPassword(),
                Set.of(SystemRole.ROLE_GLOBAL_ADMIN.name())
        );
        createUserIfNotExists(
                dummyUsersConfig.getSuperAdminUserEmail(),
                dummyUsersConfig.getSuperAdminUserUsername(),
                "Super Admin",
                dummyUsersConfig.getSuperAdminUserPassword(),
                Set.of(SystemRole.ROLE_SUPER_ADMIN.name())
        );
        createUserIfNotExists(
                dummyUsersConfig.getAdminUserEmail(),
                dummyUsersConfig.getAdminUserUsername(),
                "Admin",
                dummyUsersConfig.getAdminUserPassword(),
                Set.of(SystemRole.ROLE_ADMIN.name())
        );
    }

    private void createUserIfNotExists(String email,
                                       String username,
                                       String firstName,
                                       String password,
                                       Set<String> roleNames) {
        if (!userModelRepo.existsByRealEmail(email) && !userModelRepo.existsByUsername(username)) {
            var roles = new HashSet<>(roleModelRepo.findAllById(roleNames));
            var user = UserModel.builder()
                    .email(email)
                    .realEmail(email.toLowerCase())
                    .username(username)
                    .firstName(firstName)
                    .password(passwordEncoder.encode(password))
                    .roles(roles)
                    .emailVerified(true)
                    .createdBy("system")
                    .updatedBy("system")
                    .build();
            userModelRepo.save(user);
        }
    }
}