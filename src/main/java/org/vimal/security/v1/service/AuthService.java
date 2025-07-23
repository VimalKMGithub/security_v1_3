package org.vimal.security.v1.service;

import lombok.RequiredArgsConstructor;
import org.jose4j.lang.JoseException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.vimal.security.v1.converter.AuthAppSecretConverter;
import org.vimal.security.v1.converter.StateToken2EncrypterDecrypter;
import org.vimal.security.v1.converter.StateTokenEncrypterDecrypter;
import org.vimal.security.v1.exception.BadRequestExc;
import org.vimal.security.v1.impl.UserDetailsImpl;
import org.vimal.security.v1.model.UserModel;
import org.vimal.security.v1.repo.UserModelRepo;
import org.vimal.security.v1.service.util.CurrentUserUtil;
import org.vimal.security.v1.util.jwt.JwtUtil;
import org.vimal.security.v1.util.otp.TOTPUtil;
import org.vimal.security.v1.util.validation.ValidationsUtil;

import java.security.InvalidKeyException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class AuthService {
    private static final long STATE_TOKEN_EXPIRES_IN_SECONDS = TimeUnit.MINUTES.toSeconds(5);
    private static final String STATE_TOKEN_PREFIX = "state_token:";
    private static final String STATE_TOKEN_MAPPING_PREFIX = "state_token_mapping:";
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final TempTokenService tempTokenService;
    private final StateTokenEncrypterDecrypter stateTokenEncrypterDecrypter;
    private final StateToken2EncrypterDecrypter stateToken2EncrypterDecrypter;
    private final AuthAppSecretConverter authAppSecretConverter;
    private final UserModelRepo userModelRepo;
    private final MailService mailService;
    private final EmailMfaService emailMfaService;

    public Map<String, Object> loginByUsername(String username,
                                               String password) throws JoseException {
        try {
            ValidationsUtil.validateUsername(username);
            ValidationsUtil.validatePassword(password);
        } catch (BadRequestExc e) {
            throw new BadCredentialsException("Invalid credentials");
        }
        try {
            var authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            return handleSuccessfulLogin(authentication);
        } catch (BadCredentialsException | LockedException e) {
            if (e.getCause() instanceof UsernameNotFoundException) throw e;
            handleFailedLoginByUsername(username);
            throw e;
        }
    }

    private Map<String, Object> handleSuccessfulLogin(Authentication authentication) throws JoseException {
        var user = ((UserDetailsImpl) authentication.getPrincipal()).getUserModel();
        if (user.isMfaEnabled() && !user.getEnabledMfaMethods().isEmpty()) {
            var stateToken = generateAndStoreStateToken(user);
            return Map.of(
                    "message", "MFA required",
                    "state_token", stateToken,
                    "mfa_methods", user.getEnabledMfaMethods()
            );
        }
        return jwtUtil.generateTokens(user);
    }

    private String generateAndStoreStateToken(UserModel user) {
        var userKey = STATE_TOKEN_PREFIX + user.getId();
        var encryptedUserKey = stateTokenEncrypterDecrypter.convertToDatabaseColumn(userKey);
        var existingToken = tempTokenService.retrieveToken(encryptedUserKey);
        if (existingToken.isPresent())
            return stateToken2EncrypterDecrypter.convertToEntityAttribute(existingToken.get());
        var newStateToken = UUID.randomUUID().toString();
        var reverseLookupKey = STATE_TOKEN_MAPPING_PREFIX + newStateToken;
        var encryptedReverseLookupKey = stateTokenEncrypterDecrypter.convertToDatabaseColumn(reverseLookupKey);
        try {
            var encryptedToken = stateToken2EncrypterDecrypter.convertToDatabaseColumn(newStateToken);
            tempTokenService.storeToken(encryptedUserKey, encryptedToken, Duration.ofSeconds(STATE_TOKEN_EXPIRES_IN_SECONDS));
            var encryptedUserId = stateToken2EncrypterDecrypter.convertToDatabaseColumn(user.getId().toString());
            tempTokenService.storeToken(encryptedReverseLookupKey, encryptedUserId, Duration.ofSeconds(STATE_TOKEN_EXPIRES_IN_SECONDS));
            return newStateToken;
        } catch (Exception e) {
            tempTokenService.removeToken(encryptedUserKey);
            tempTokenService.removeToken(encryptedReverseLookupKey);
            throw new RuntimeException("Failed to generate state token: " + e.getMessage(), e);
        }
    }

    private void handleFailedLoginByUsername(String username) {
        var user = userModelRepo.findByUsername(username).orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
        user.recordFailedLoginAttempt();
        userModelRepo.save(user);
    }

    public Map<String, Object> loginByEmail(String email,
                                            String password) throws JoseException {
        try {
            ValidationsUtil.validateEmail(email);
            ValidationsUtil.validatePassword(password);
        } catch (BadRequestExc e) {
            throw new BadCredentialsException("Invalid credentials");
        }
        var user = userModelRepo.findByEmail(email).orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
        try {
            var authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), password));
            return handleSuccessfulLogin(authentication);
        } catch (BadCredentialsException | LockedException e) {
            if (e.getCause() instanceof UsernameNotFoundException) throw e;
            handleFailedLoginByUser(user);
            throw e;
        }
    }

    private void handleFailedLoginByUser(UserModel user) {
        user.recordFailedLoginAttempt();
        userModelRepo.save(user);
    }

    public ResponseEntity<?> login(String usernameOrEmail,
                                   String password) throws JoseException {
        try {
            ValidationsUtil.validateString(usernameOrEmail, "Username/email");
            ValidationsUtil.validatePassword(password);
        } catch (BadRequestExc e) {
            throw new BadCredentialsException("Invalid credentials");
        }
        if (ValidationsUtil.EMAIL_PATTERN.matcher(usernameOrEmail).matches())
            return ResponseEntity.ok(loginByEmail(usernameOrEmail, password));
        else if (ValidationsUtil.USERNAME_PATTERN.matcher(usernameOrEmail).matches())
            return ResponseEntity.ok(loginByUsername(usernameOrEmail, password));
        else throw new BadCredentialsException("Invalid credentials");
    }

    public Map<String, Object> logout() {
        var user = CurrentUserUtil.getCurrentAuthenticatedUser();
        jwtUtil.revokeAccessToken(user);
        jwtUtil.revokeRefreshTokenByUser(user);
        return Map.of("message", "Logout successful");
    }

    public Map<String, Object> refreshAccessToken(String refreshToken) throws JoseException {
        try {
            ValidationsUtil.validateUuid(refreshToken);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Invalid refresh token");
        }
        return jwtUtil.refreshAccessToken(refreshToken);
    }

    public Map<String, Object> revokeAccessToken() {
        var authenticatedUser = CurrentUserUtil.getCurrentAuthenticatedUser();
        jwtUtil.revokeAccessToken(authenticatedUser);
        return Map.of("message", "Access token revoked successfully");
    }

    public Map<String, Object> revokeRefreshToken(String refreshToken) {
        try {
            ValidationsUtil.validateUuid(refreshToken);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Invalid refresh token");
        }
        jwtUtil.revokeRefreshToken(refreshToken);
        return Map.of("message", "Refresh token revoked successfully");
    }

    public Map<String, String> sendOtpToVerifyEmailMfa(String stateToken) {
        try {
            ValidationsUtil.validateUuid(stateToken);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Invalid state token");
        }
        var user = getUserByStateToken(stateToken);
        if (!user.hasMfaEnabled(UserModel.MfaType.EMAIL)) throw new BadRequestExc("Email Mfa is not enabled");
        var otp = emailMfaService.generateAndStoreEmailOtpForMFA(user);
        mailService.sendOtpAsync(user.getEmail(), "OTP to verify Email MFA", otp);
        return Map.of(
                "message", "OTP sent to your registered email address. Please check your email to continue"
        );
    }

    private UserModel getUserByStateToken(String stateToken) {
        var encryptedReverseLookupKey = getEncryptedReverseLookupKey(stateToken);
        var userId = getIdByEncryptedReverseLookupKey(encryptedReverseLookupKey);
        return userModelRepo.findById(UUID.fromString(userId)).orElseThrow(() -> new BadRequestExc("User not found"));
    }

    private String getEncryptedReverseLookupKey(String token) {
        var reverseLookupKey = STATE_TOKEN_MAPPING_PREFIX + token;
        return stateTokenEncrypterDecrypter.convertToDatabaseColumn(reverseLookupKey);
    }

    private String getIdByEncryptedReverseLookupKey(String encryptedReverseLookupKey) {
        var encryptedUserId = tempTokenService.retrieveToken(encryptedReverseLookupKey).orElseThrow(() -> new BadRequestExc("Expired state token"));
        return stateToken2EncrypterDecrypter.convertToEntityAttribute(encryptedUserId);
    }

    public Map<String, Object> verifyEmailOtp(String otp,
                                              String stateToken) throws JoseException {
        try {
            ValidationsUtil.validateOtpTotp(otp);
            ValidationsUtil.validateUuid(stateToken);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Invalid OTP or state token");
        }
        var encryptedReverseLookupKey = getEncryptedReverseLookupKey(stateToken);
        var userId = getIdByEncryptedReverseLookupKey(encryptedReverseLookupKey);
        var user = userModelRepo.findById(UUID.fromString(userId)).orElseThrow(() -> new BadRequestExc("User not found"));
        if (!user.hasMfaEnabled(UserModel.MfaType.EMAIL)) throw new BadRequestExc("Email Mfa is not enabled");
        emailMfaService.verifyOtpToLogin(user, otp);
        try {
            var userKey = STATE_TOKEN_PREFIX + user.getId();
            var encryptedKey = stateTokenEncrypterDecrypter.convertToDatabaseColumn(userKey);
            tempTokenService.removeToken(encryptedKey);
            tempTokenService.removeToken(encryptedReverseLookupKey);
        } catch (Exception ignored) {
        }
        return jwtUtil.generateTokens(user);
    }

    public Map<String, Object> verifyAuthAppOtp(String totp,
                                                String stateToken) throws JoseException, InvalidKeyException {
        try {
            ValidationsUtil.validateOtpTotp(totp);
            ValidationsUtil.validateUuid(stateToken);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Invalid TOTP or state token");
        }
        var encryptedReverseLookupKey = getEncryptedReverseLookupKey(stateToken);
        var userId = getIdByEncryptedReverseLookupKey(encryptedReverseLookupKey);
        var user = userModelRepo.findById(UUID.fromString(userId)).orElseThrow(() -> new BadRequestExc("User not found"));
        if (!user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
            throw new BadRequestExc("Authenticator App Mfa is not enabled");
        if (user.isAccountLocked() && user.getLastLockedAt().plus(1, ChronoUnit.DAYS).isAfter(Instant.now()))
            throw new LockedException("Account is locked due to too many failed mfa attempts. Please try again later");
        if (!TOTPUtil.verifyOTP(authAppSecretConverter.convertToEntityAttribute(user.getAuthAppSecret()), totp)) {
            handleFailedMfaAttempt(user);
            throw new BadRequestExc("Invalid TOTP");
        }
        try {
            var userKey = STATE_TOKEN_PREFIX + user.getId();
            var encryptedKey = stateTokenEncrypterDecrypter.convertToDatabaseColumn(userKey);
            tempTokenService.removeToken(encryptedKey);
            tempTokenService.removeToken(encryptedReverseLookupKey);
        } catch (Exception ignored) {
        }
        return jwtUtil.generateTokens(user);
    }

    private void handleFailedMfaAttempt(UserModel user) {
        user.recordFailedMfaAttempt();
        userModelRepo.save(user);
    }
}