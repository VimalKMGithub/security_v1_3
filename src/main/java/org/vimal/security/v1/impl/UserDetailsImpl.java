package org.vimal.security.v1.impl;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.vimal.security.v1.model.UserModel;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class UserDetailsImpl implements UserDetails {
    @Getter
    private final UserModel userModel;
    private final Set<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(UserModel userModel) {
        this.userModel = userModel;
        this.authorities = computeAuthorities(userModel);
    }

    public UserDetailsImpl(UserModel userModel,
                           Set<? extends GrantedAuthority> authorities) {
        this.userModel = userModel;
        this.authorities = authorities;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    private Set<GrantedAuthority> computeAuthorities(UserModel userModel) {
        Set<GrantedAuthority> computedAuthorities = new HashSet<>();
        userModel.getRoles().forEach(role -> computedAuthorities.add(new SimpleGrantedAuthority(role.getRoleName())));
        userModel.getRoles().stream()
                .flatMap(role -> role.getPermissions().stream())
                .forEach(permission -> computedAuthorities.add(new SimpleGrantedAuthority(permission.getPermissionName())));
        return computedAuthorities;
    }

    @Override
    public String getPassword() {
        return userModel.getPassword();
    }

    @Override
    public String getUsername() {
        return userModel.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return userModel.getCreatedAt().plus(36500, ChronoUnit.DAYS).isAfter(Instant.now());
    }

    @Override
    public boolean isAccountNonLocked() {
        return !userModel.isAccountLocked() || userModel.getLastLockedAt().plus(1, ChronoUnit.DAYS).isBefore(Instant.now());
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return userModel.getPasswordChangedAt().plus(365, ChronoUnit.DAYS).isAfter(Instant.now());
    }

    @Override
    public boolean isEnabled() {
        return userModel.isAccountEnabled();
    }

    public String getEmail() {
        return userModel.getEmail();
    }
}