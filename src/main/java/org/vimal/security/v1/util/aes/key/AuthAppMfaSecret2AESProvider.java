package org.vimal.security.v1.util.aes.key;

import lombok.Getter;
import org.springframework.context.annotation.Configuration;
import org.vimal.security.v1.config.properties.AesConfig;

@Configuration
public class AuthAppMfaSecret2AESProvider implements AESKeyProvider {
    @Getter
    private final String aesSecret;

    public AuthAppMfaSecret2AESProvider(AesConfig aesConfig) {
        this.aesSecret = aesConfig.getForAuthAppMfaSecret2();
    }
}