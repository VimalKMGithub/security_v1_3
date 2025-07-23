package org.vimal.security.v1.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v1.converter.EmailOtpForMfa2EncrypterDecrypter;
import org.vimal.security.v1.converter.EmailOtpForMfaEncrypterDecrypter;
import org.vimal.security.v1.exception.BadRequestExc;
import org.vimal.security.v1.model.UserModel;
import org.vimal.security.v1.repo.UserModelRepo;
import org.vimal.security.v1.service.util.CurrentUserUtil;
import org.vimal.security.v1.util.jwt.JwtUtil;
import org.vimal.security.v1.util.otp.OtpUtil;
import org.vimal.security.v1.util.validation.ValidationsUtil;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class EmailMfaService {
    private final PasswordEncoder passwordEncoder;
    private static final String EMAIL_MFA_OTP_PREFIX = "email_mfa_otp:";
    private static final long OTP_EXPIRES_IN_SECONDS = TimeUnit.MINUTES.toSeconds(5);
    private final UserModelRepo userModelRepo;
    private final MailService mailService;
    private final TempTokenService tempTokenService;
    private final EmailOtpForMfaEncrypterDecrypter emailOtpForMfaEncrypterDecrypter;
    private final EmailOtpForMfa2EncrypterDecrypter emailOtpForMfa2EncrypterDecrypter;
    private final JwtUtil jwtUtil;

    public Map<String, String> sendOtpToEnableEmailMfa() {
        var user = CurrentUserUtil.getCurrentAuthenticatedUser();
        if (user.hasMfaEnabled(UserModel.MfaType.EMAIL)) throw new BadRequestExc("Email Mfa is already enabled");
        var otp = generateAndStoreEmailOtpForMFA(user);
        mailService.sendOtpAsync(user.getEmail(), "Otp to enable email mfa", otp);
        return Map.of(
                "message", "OTP sent to your registered email address. Please check your email to continue"
        );
    }

    public String generateAndStoreEmailOtpForMFA(UserModel user) {
        var otp = OtpUtil.generateOtp();
        var userKey = buildCacheKey(user);
        var encryptedKey = emailOtpForMfaEncrypterDecrypter.convertToDatabaseColumn(userKey);
        var encryptedOtp = emailOtpForMfa2EncrypterDecrypter.convertToDatabaseColumn(otp);
        tempTokenService.storeToken(encryptedKey, encryptedOtp, Duration.ofSeconds(OTP_EXPIRES_IN_SECONDS));
        return otp;
    }

    private String buildCacheKey(UserModel user) {
        return EMAIL_MFA_OTP_PREFIX + user.getId();
    }

    public Map<String, String> verifyOtpToEnableEmailMfa(String otp) {
        try {
            ValidationsUtil.validateOtpTotp(otp);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Invalid OTP");
        }
        var user = CurrentUserUtil.getCurrentAuthenticatedUser();
        if (user.hasMfaEnabled(UserModel.MfaType.EMAIL)) throw new BadRequestExc("Email Mfa is already enabled");
        verifyOtp(user, otp);
        user = userModelRepo.findById(user.getId()).orElseThrow(() -> new BadRequestExc("User not found"));
        user.enableMfaMethod(UserModel.MfaType.EMAIL);
        user.setUpdatedBy("Self email mfa enabled");
        userModelRepo.save(user);
        jwtUtil.revokeAccessToken(user);
        jwtUtil.revokeRefreshTokenByUser(user);
        return Map.of("message", "Email Mfa enabled successfully. Please log in again to continue");
    }

    private void verifyOtp(UserModel user,
                           String otp) {
        var cacheKey = buildCacheKey(user);
        var encryptedKey = emailOtpForMfaEncrypterDecrypter.convertToDatabaseColumn(cacheKey);
        var storedOtp = tempTokenService.retrieveToken(encryptedKey).orElseThrow(() -> new BadRequestExc("Expired OTP"));
        var decryptedStoredOtp = emailOtpForMfa2EncrypterDecrypter.convertToEntityAttribute(storedOtp);
        if (!decryptedStoredOtp.equals(otp)) throw new BadRequestExc("Invalid OTP");
        tempTokenService.removeToken(encryptedKey);
    }

    public void verifyOtpToLogin(UserModel user,
                                 String otp) {
        if (user.isAccountLocked() && user.getLastLockedAt().plus(1, ChronoUnit.DAYS).isAfter(Instant.now()))
            throw new LockedException("Account is locked due to too many failed mfa attempts. Please try again later");
        var cacheKey = buildCacheKey(user);
        var encryptedKey = emailOtpForMfaEncrypterDecrypter.convertToDatabaseColumn(cacheKey);
        var storedOtp = tempTokenService.retrieveToken(encryptedKey);
        if (storedOtp.isEmpty()) {
            handleFailedMfaAttempt(user);
            throw new BadRequestExc("Expired OTP");
        }
        var decryptedStoredOtp = emailOtpForMfa2EncrypterDecrypter.convertToEntityAttribute(storedOtp.get());
        if (!decryptedStoredOtp.equals(otp)) {
            handleFailedMfaAttempt(user);
            throw new BadRequestExc("Invalid OTP");
        }
        user.recordSuccessfulMfaAttempt();
        try {
            tempTokenService.removeToken(encryptedKey);
        } catch (Exception ignored) {
        }
    }

    private void handleFailedMfaAttempt(UserModel user) {
        user.recordFailedMfaAttempt();
        userModelRepo.save(user);
    }

    public Map<String, String> disableEmailMfa(String password) {
        try {
            ValidationsUtil.validatePassword(password);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Invalid password");
        }
        var user = CurrentUserUtil.getCurrentAuthenticatedUser();
        if (!user.hasMfaEnabled(UserModel.MfaType.EMAIL)) throw new BadRequestExc("Email Mfa is already disabled");
        user = userModelRepo.findById(user.getId()).orElseThrow(() -> new BadRequestExc("User not found"));
        if (!passwordEncoder.matches(password, user.getPassword())) throw new BadRequestExc("Invalid password");
        user.disableMfaMethod(UserModel.MfaType.EMAIL);
        user.setUpdatedBy("Self email mfa disabling");
        userModelRepo.save(user);
        jwtUtil.revokeAccessToken(user);
        jwtUtil.revokeRefreshTokenByUser(user);
        return Map.of("message", "Email Mfa disabled successfully. Please log in again to continue");
    }
}