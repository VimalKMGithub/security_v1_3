package org.vimal.security.v1.util.aes.factory;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.vimal.security.v1.util.aes.AESInterface;
import org.vimal.security.v1.util.aes.AESOperationType;
import org.vimal.security.v1.util.aes.DeterministicAESUtil;
import org.vimal.security.v1.util.aes.RandomAESUtil;
import org.vimal.security.v1.util.aes.key.*;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
@RequiredArgsConstructor
public class AESUtilFactory {
    private final EmailVerificationTokenAESProvider emailVerificationTokenAESKeyConfig;
    private final EmailVerificationToken2AESProvider emailVerificationToken2AESKeyConfig;
    private final JwtIdAESProvider jwtIdAESKeyConfig;
    private final JwtId2AESProvider jwtId2AESKeyConfig;
    private final RefreshTokenAESProvider refreshTokenAESKeyConfig;
    private final RefreshToken2AESProvider refreshToken2AESKeyConfig;
    private final EmailOtpForMfaAESProvider emailOtpForMfaAESKeyConfig;
    private final EmailOtpForMfa2AESProvider emailOtpForMfa2AESKeyConfig;
    private final AuthAppMfaSecretAESProvider authAppMfaSecretAESKeyConfig;
    private final AuthAppMfaSecret2AESProvider authAppMfaSecret2AESKeyConfig;
    private final AuthAppSecretAESProvider authAppSecretAESKeyConfig;
    private final StateTokenAESProvider stateTokenAESKeyConfig;
    private final StateToken2AESProvider stateToken2AESKeyConfig;
    private final EmailOtpForgotPwdAESProvider emailOtpForgotPwdAESKeyConfig;
    private final EmailOtpForgotPwd2AESProvider emailOtpForgotPwd2AESKeyConfig;
    private final EmailOtpEmailChangeAESProvider emailOtpEmailChangeAESKeyConfig;
    private final EmailOtpEmailChange2AESProvider emailOtpEmailChange2AESKeyConfig;
    private final EmailStoreEmailChangeAESProvider emailStoreEmailChangeAESKeyConfig;
    private final EmailStoreEmailChange2AESProvider emailStoreEmailChange2AESKeyConfig;
    private final EmailOtpToDeleteAccountAESProvider emailOtpToDeleteAccountAESKeyConfig;
    private final EmailOtpToDeleteAccount2AESProvider emailOtpToDeleteAccount2AESKeyConfig;

    private final Map<AESOperationType, AESInterface> cache = new ConcurrentHashMap<>();

    public AESInterface getUtil(AESOperationType type) {
        return cache.computeIfAbsent(type, this::createUtil);
    }

    private AESInterface createUtil(AESOperationType type) {
        return switch (type) {
            case EMAIL_VERIFICATION_TOKEN -> new DeterministicAESUtil(emailVerificationTokenAESKeyConfig);
            case EMAIL_VERIFICATION_TOKEN_2 -> new RandomAESUtil(emailVerificationToken2AESKeyConfig);
            case JWT_ID -> new DeterministicAESUtil(jwtIdAESKeyConfig);
            case JWT_ID_2 -> new RandomAESUtil(jwtId2AESKeyConfig);
            case REFRESH_TOKEN -> new DeterministicAESUtil(refreshTokenAESKeyConfig);
            case REFRESH_TOKEN_2 -> new RandomAESUtil(refreshToken2AESKeyConfig);
            case EMAIL_OTP_FOR_MFA -> new DeterministicAESUtil(emailOtpForMfaAESKeyConfig);
            case EMAIL_OTP_FOR_MFA_2 -> new RandomAESUtil(emailOtpForMfa2AESKeyConfig);
            case AUTH_APP_MFA_SECRET -> new DeterministicAESUtil(authAppMfaSecretAESKeyConfig);
            case AUTH_APP_MFA_SECRET_2 -> new RandomAESUtil(authAppMfaSecret2AESKeyConfig);
            case AUTH_APP_SECRET -> new RandomAESUtil(authAppSecretAESKeyConfig);
            case STATE_TOKEN -> new DeterministicAESUtil(stateTokenAESKeyConfig);
            case STATE_TOKEN_2 -> new RandomAESUtil(stateToken2AESKeyConfig);
            case EMAIL_OTP_FORGOT_PWD -> new DeterministicAESUtil(emailOtpForgotPwdAESKeyConfig);
            case EMAIL_OTP_FORGOT_PWD_2 -> new RandomAESUtil(emailOtpForgotPwd2AESKeyConfig);
            case EMAIL_OTP_EMAIL_CHANGE -> new DeterministicAESUtil(emailOtpEmailChangeAESKeyConfig);
            case EMAIL_OTP_EMAIL_CHANGE_2 -> new RandomAESUtil(emailOtpEmailChange2AESKeyConfig);
            case EMAIL_STORE_EMAIL_CHANGE -> new DeterministicAESUtil(emailStoreEmailChangeAESKeyConfig);
            case EMAIL_STORE_EMAIL_CHANGE_2 -> new RandomAESUtil(emailStoreEmailChange2AESKeyConfig);
            case EMAIL_OTP_DELETE_ACCOUNT -> new DeterministicAESUtil(emailOtpToDeleteAccountAESKeyConfig);
            case EMAIL_OTP_DELETE_ACCOUNT_2 -> new RandomAESUtil(emailOtpToDeleteAccount2AESKeyConfig);
        };
    }
}