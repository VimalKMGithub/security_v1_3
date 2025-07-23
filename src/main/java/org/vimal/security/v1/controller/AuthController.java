package org.vimal.security.v1.controller;

import lombok.RequiredArgsConstructor;
import org.jose4j.lang.JoseException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.vimal.security.v1.service.AuthService;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/login-by-username")
    public ResponseEntity<?> loginByUsername(@RequestParam String username,
                                             @RequestParam String password) throws JoseException {
        return ResponseEntity.ok(authService.loginByUsername(username, password));
    }

    @PostMapping("/login-by-email")
    public ResponseEntity<?> loginByEmail(@RequestParam String email,
                                          @RequestParam String password) throws JoseException {
        return ResponseEntity.ok(authService.loginByEmail(email, password));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String usernameOrEmail,
                                   @RequestParam String password) throws JoseException {
        return authService.login(usernameOrEmail, password);
    }

    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> logout() {
        return ResponseEntity.ok(authService.logout());
    }

    @PostMapping("/refresh-access-token")
    public ResponseEntity<?> refreshAccessToken(@RequestParam String refreshToken) throws JoseException {
        return ResponseEntity.ok(authService.refreshAccessToken(refreshToken));
    }

    @PostMapping("/revoke-access-token")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> revokeAccessToken() {
        return ResponseEntity.ok(authService.revokeAccessToken());
    }

    @PostMapping("/revoke-refresh-token")
    public ResponseEntity<?> revokeRefreshToken(@RequestParam String refreshToken) {
        return ResponseEntity.ok(authService.revokeRefreshToken(refreshToken));
    }
}