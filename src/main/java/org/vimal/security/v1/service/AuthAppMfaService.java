package org.vimal.security.v1.service;

import com.google.zxing.WriterException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v1.converter.AuthAppMfaSecret2EncrypterDecrypter;
import org.vimal.security.v1.converter.AuthAppMfaSecretEncrypterDecrypter;
import org.vimal.security.v1.converter.AuthAppSecretConverter;
import org.vimal.security.v1.exception.BadRequestExc;
import org.vimal.security.v1.model.UserModel;
import org.vimal.security.v1.repo.UserModelRepo;
import org.vimal.security.v1.service.util.CurrentUserUtil;
import org.vimal.security.v1.util.jwt.JwtUtil;
import org.vimal.security.v1.util.otp.TOTPUtil;
import org.vimal.security.v1.util.qr.QRUtil;
import org.vimal.security.v1.util.validation.ValidationsUtil;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class AuthAppMfaService {
    private static final String AUTH_APP_MFA_SECRET_PREFIX = "auth_app_mfa_secret:";
    private static final String ISSUER_NAME = "God Level Security";
    private static final long SECRET_EXPIRES_IN_SECONDS = TimeUnit.MINUTES.toSeconds(5);
    private final TempTokenService tempTokenService;
    private final PasswordEncoder passwordEncoder;
    private final UserModelRepo userModelRepo;
    private final AuthAppMfaSecretEncrypterDecrypter authAppMfaSecretEncrypterDecrypter;
    private final AuthAppMfaSecret2EncrypterDecrypter authAppMfaSecret2EncrypterDecrypter;
    private final AuthAppSecretConverter authAppSecretConverter;
    private final JwtUtil jwtUtil;

    public byte[] generateQRCodeForAuthApp() throws NoSuchAlgorithmException, IOException, WriterException {
        var user = CurrentUserUtil.getCurrentAuthenticatedUser();
        if (user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
            throw new BadRequestExc("Authenticator app Mfa is already enabled");
        var secret = generateAndStoreAuthAppSecretForMFA(user);
        return QRUtil.generateQRCode(TOTPUtil.generateTOTPUrl(ISSUER_NAME, user.getUsername(), secret));
    }

    private String generateAndStoreAuthAppSecretForMFA(UserModel user) throws NoSuchAlgorithmException {
        var userKey = buildCacheKey(user);
        var secret = TOTPUtil.generateBase32Secret();
        var encryptedUserKey = authAppMfaSecretEncrypterDecrypter.convertToDatabaseColumn(userKey);
        var encryptedSecret = authAppMfaSecret2EncrypterDecrypter.convertToDatabaseColumn(secret);
        tempTokenService.storeToken(encryptedUserKey, encryptedSecret, Duration.ofSeconds(SECRET_EXPIRES_IN_SECONDS));
        return secret;
    }

    private String buildCacheKey(UserModel user) {
        return AUTH_APP_MFA_SECRET_PREFIX + user.getId();
    }

    public Map<String, String> verifyTotpToSetupAuthApp(String totp) throws InvalidKeyException {
        try {
            ValidationsUtil.validateOtpTotp(totp);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Invalid TOTP");
        }
        var user = CurrentUserUtil.getCurrentAuthenticatedUser();
        if (user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
            throw new BadRequestExc("Authenticator app Mfa is already enabled");
        user = userModelRepo.findById(user.getId()).orElseThrow(() -> new BadRequestExc("User not found"));
        verifyTotp(user, totp);
        jwtUtil.revokeAccessToken(user);
        jwtUtil.revokeRefreshTokenByUser(user);
        return Map.of("message", "Authenticator app Mfa enabled successfully. Please log in again to continue");
    }

    private void verifyTotp(UserModel user,
                            String totp) throws InvalidKeyException {
        var cacheKey = buildCacheKey(user);
        var encryptedKey = authAppMfaSecretEncrypterDecrypter.convertToDatabaseColumn(cacheKey);
        var storedSecret = tempTokenService.retrieveToken(encryptedKey).orElseThrow(() -> new BadRequestExc("Request expired"));
        var decryptedStoredSecret = authAppMfaSecret2EncrypterDecrypter.convertToEntityAttribute(storedSecret);
        if (TOTPUtil.verifyOTP(decryptedStoredSecret, totp)) {
            user.enableMfaMethod(UserModel.MfaType.AUTHENTICATOR_APP);
            user.setAuthAppSecret(authAppSecretConverter.convertToDatabaseColumn(decryptedStoredSecret));
            user.setUpdatedBy("Self auth app setup");
            userModelRepo.save(user);
            try {
                tempTokenService.removeToken(encryptedKey);
            } catch (Exception ignored) {
            }
            return;
        }
        throw new BadRequestExc("Invalid TOTP");
    }

    public Map<String, String> disableAuthApp(String password) {
        try {
            ValidationsUtil.validatePassword(password);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Invalid password");
        }
        var user = CurrentUserUtil.getCurrentAuthenticatedUser();
        if (!user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
            throw new BadRequestExc("Authenticator app Mfa is already disabled");
        user = userModelRepo.findById(user.getId()).orElseThrow(() -> new BadRequestExc("User not found"));
        if (!passwordEncoder.matches(password, user.getPassword())) throw new BadRequestExc("Invalid password");
        user.disableMfaMethod(UserModel.MfaType.AUTHENTICATOR_APP);
        user.setAuthAppSecret(null);
        user.setUpdatedBy("Self auth app disable");
        userModelRepo.save(user);
        jwtUtil.revokeAccessToken(user);
        jwtUtil.revokeRefreshTokenByUser(user);
        return Map.of("message", "Authenticator app Mfa disabled successfully. Please log in again to continue");
    }
}