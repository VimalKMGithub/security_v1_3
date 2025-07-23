package org.vimal.security.v1.impl;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.vimal.security.v1.exception.customauthexception.CustomLockedExc;
import org.vimal.security.v1.exception.customauthexception.EmailNotVerifiedExc;
import org.vimal.security.v1.model.UserModel;
import org.vimal.security.v1.repo.UserModelRepo;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Component
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserModelRepo userModelRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var user = userModelRepo.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("Invalid credentials"));
        checkAccountStatus(user);
        return new UserDetailsImpl(user);
    }

    private void checkAccountStatus(UserModel user) {
        if (!user.isEmailVerified()) throw new EmailNotVerifiedExc("Please verify your email first");
        if (user.isAccountLocked() && user.getLastLockedAt().plus(1, ChronoUnit.DAYS).isAfter(Instant.now()))
            throw new CustomLockedExc("Account is temporarily locked. Please try again later.");
    }
}