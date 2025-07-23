package org.vimal.security.v1.util.aes.key;

import lombok.Getter;
import org.springframework.context.annotation.Configuration;
import org.vimal.security.v1.config.properties.AesConfig;

@Configuration
public class EmailOtpForgotPwdAESProvider implements AESKeyProvider {
    @Getter
    private final String aesSecret;

    public EmailOtpForgotPwdAESProvider(AesConfig aesConfig) {
        this.aesSecret = aesConfig.getForEmailOtpForgotPwd();
    }
}