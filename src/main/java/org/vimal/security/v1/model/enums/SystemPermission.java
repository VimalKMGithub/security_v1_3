package org.vimal.security.v1.model.enums;

import lombok.Getter;

@Getter
public enum SystemPermission {
    CAN_CREATE_USER("Permission to Create User"),
    CAN_READ_USER("Permission to Read User"),
    CAN_UPDATE_USER("Permission to Update User"),
    CAN_DELETE_USER("Permission to Delete User"),

    CAN_READ_PERMISSION("Permission to Read Permission"),

    CAN_CREATE_ROLE("Permission to Create Role"),
    CAN_READ_ROLE("Permission to Read Role"),
    CAN_UPDATE_ROLE("Permission to Update Role"),
    CAN_DELETE_ROLE("Permission to Delete Role");

    private final String description;

    SystemPermission(String description) {
        this.description = description;
    }
}