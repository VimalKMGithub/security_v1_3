package org.vimal.security.v1.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "aes.secret")
@Getter
@Setter
public class AesConfig {
    private String emailVerificationToken;
    private String emailVerificationToken2;
    private String jwtId;
    private String jwtId2;
    private String refreshToken;
    private String refreshToken2;
    private String forEmailMfa;
    private String forEmailMfa2;
    private String forAuthAppMfaSecret;
    private String forAuthAppMfaSecret2;
    private String authAppSecret;
    private String stateToken;
    private String stateToken2;
    private String forEmailOtpForgotPwd;
    private String forEmailOtpForgotPwd2;
    private String forEmailOtpEmailChange;
    private String forEmailOtpEmailChange2;
    private String forEmailStoreEmailChange;
    private String forEmailStoreEmailChange2;
    private String forEmailOtpDeleteAccount;
    private String forEmailOtpDeleteAccount2;
}