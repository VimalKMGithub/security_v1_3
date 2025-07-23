package org.vimal.security.v1.service.util;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.vimal.security.v1.impl.UserDetailsImpl;
import org.vimal.security.v1.model.UserModel;
import org.vimal.security.v1.model.enums.SystemRole;

import java.util.Comparator;

public final class CurrentUserUtil {
    private CurrentUserUtil() {
        throw new AssertionError("Cannot instantiate CurrentUserUtil class");
    }

    public static Authentication getAuthenticationOfCurrentAuthenticatedUser() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || !(authentication.getPrincipal() instanceof UserDetailsImpl))
            throw new AuthenticationCredentialsNotFoundException("User not authenticated");
        return authentication;
    }

    public static UserModel getCurrentAuthenticatedUser() {
        var userDetails = (UserDetailsImpl) getAuthenticationOfCurrentAuthenticatedUser().getPrincipal();
        return userDetails.getUserModel();
    }

    public static String getCurrentAuthenticatedUserHighestAdminRole() {
        return getAuthenticationOfCurrentAuthenticatedUser().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(SystemRole.TOP_ROLES::contains)
                .min(Comparator.comparingInt(SystemRole.TOP_ROLES::indexOf))
                .orElse(null);
    }
}