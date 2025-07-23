package org.vimal.security.v1.model.enums;

import lombok.Getter;

import java.util.List;

@Getter
public enum SystemRole {
    ROLE_GOD("Role God"),
    ROLE_GLOBAL_ADMIN("Role Global Admin"),
    ROLE_SUPER_ADMIN("Role Super Admin"),
    ROLE_ADMIN("Role Admin"),
    ROLE_MANAGE_ROLES("Role Manager"),
    ROLE_MANAGE_USERS("Role User Manager"),
    ROLE_MANAGE_PERMISSIONS("Role Permission Manager");

    private final String description;

    SystemRole(String description) {
        this.description = description;
    }

    public static final List<String> TOP_ROLES = List.of(
            ROLE_GOD.name(),
            ROLE_GLOBAL_ADMIN.name(),
            ROLE_SUPER_ADMIN.name(),
            ROLE_ADMIN.name()
    );
}