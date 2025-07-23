package org.vimal.security.v1.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.vimal.security.v1.model.enums.SystemPermission;
import org.vimal.security.v1.model.enums.SystemRole;
import org.vimal.security.v1.service.util.CurrentUserUtil;

import java.util.Set;

@Service("authz")
public class AuthorizationService {
    public boolean isAdminOrAbove() {
        return hasAnyAuthority(SystemRole.TOP_ROLES.toArray(new String[0]));
    }

    public boolean canCreateUsers() {
        return hasAuthority(SystemPermission.CAN_CREATE_USER.name());
    }

    public boolean canReadUsers() {
        return hasAuthority(SystemPermission.CAN_READ_USER.name());
    }

    public boolean canUpdateUsers() {
        return hasAuthority(SystemPermission.CAN_UPDATE_USER.name());
    }

    public boolean canDeleteUsers() {
        return hasAuthority(SystemPermission.CAN_DELETE_USER.name());
    }

    public boolean canReadPermissions() {
        return hasAuthority(SystemPermission.CAN_READ_PERMISSION.name());
    }

    public boolean canCreateRoles() {
        return hasAuthority(SystemPermission.CAN_CREATE_ROLE.name());
    }

    public boolean canReadRoles() {
        return hasAuthority(SystemPermission.CAN_READ_ROLE.name());
    }

    public boolean canUpdateRoles() {
        return hasAuthority(SystemPermission.CAN_UPDATE_ROLE.name());
    }

    public boolean canDeleteRoles() {
        return hasAuthority(SystemPermission.CAN_DELETE_ROLE.name());
    }

    public boolean hasAuthority(String authority) {
        return hasAnyAuthority(authority);
    }

    public boolean hasAnyAuthority(String... authorities) {
        var auth = CurrentUserUtil.getAuthenticationOfCurrentAuthenticatedUser();
        var requiredRoles = Set.of(authorities);
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(requiredRoles::contains);
    }
}