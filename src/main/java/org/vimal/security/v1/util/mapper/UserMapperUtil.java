package org.vimal.security.v1.util.mapper;

import org.vimal.security.v1.dto.UserSummaryDto;
import org.vimal.security.v1.model.RoleModel;
import org.vimal.security.v1.model.UserModel;

import java.util.stream.Collectors;

public final class UserMapperUtil {
    private UserMapperUtil() {
        throw new AssertionError("Cannot instantiate UserMapperUtil class");
    }

    public static UserSummaryDto toSummaryDto(UserModel user) {
        var dto = new UserSummaryDto();
        dto.setId(user.getId());
        dto.setFirstName(user.getFirstName());
        dto.setMiddleName(user.getMiddleName());
        dto.setLastName(user.getLastName());
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setEmailVerified(user.isEmailVerified());
        dto.setMfaEnabled(user.isMfaEnabled());
        dto.setMfaMethods(user.getEnabledMfaMethods());
        dto.setAccountLocked(user.isAccountLocked());
        dto.setAccountEnabled(user.isAccountEnabled());
        dto.setFailedLoginAttempts(user.getFailedLoginAttempts());
        dto.setFailedMfaAttempts(user.getFailedMfaAttempts());
        dto.setRoles(user.getRoles().stream().map(RoleModel::getRoleName)
                .collect(Collectors.toSet()));
        dto.setLastLoginAt(user.getLastLoginAt());
        dto.setPasswordChangedAt(user.getPasswordChangedAt());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setUpdatedAt(user.getUpdatedAt());
        dto.setLastLockedAt(user.getLastLockedAt());
        dto.setCreatedBy(user.getCreatedBy());
        dto.setUpdatedBy(user.getUpdatedBy());
        return dto;
    }
}