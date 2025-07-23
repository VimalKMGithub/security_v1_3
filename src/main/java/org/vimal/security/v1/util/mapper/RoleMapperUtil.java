package org.vimal.security.v1.util.mapper;

import org.vimal.security.v1.dto.RoleSummaryDto;
import org.vimal.security.v1.model.PermissionModel;
import org.vimal.security.v1.model.RoleModel;

import java.util.stream.Collectors;

public final class RoleMapperUtil {
    private RoleMapperUtil() {
        throw new AssertionError("Cannot instantiate RoleMapperUtil class");
    }

    public static RoleSummaryDto toSummaryDto(RoleModel role) {
        var dto = new RoleSummaryDto();
        dto.setRoleName(role.getRoleName());
        dto.setDescription(role.getDescription());
        dto.setSystemRole(role.isSystemRole());
        dto.setPermissions(role.getPermissions().stream()
                .map(PermissionModel::getPermissionName)
                .collect(Collectors.toSet()));
        dto.setCreatedAt(role.getCreatedAt());
        dto.setUpdatedAt(role.getUpdatedAt());
        dto.setCreatedBy(role.getCreatedBy());
        dto.setUpdatedBy(role.getUpdatedBy());
        return dto;
    }
}