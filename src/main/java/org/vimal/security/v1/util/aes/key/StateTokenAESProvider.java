package org.vimal.security.v1.util.aes.key;

import lombok.Getter;
import org.springframework.context.annotation.Configuration;
import org.vimal.security.v1.config.properties.AesConfig;

@Configuration
public class StateTokenAESProvider implements AESKeyProvider {
    @Getter
    private final String aesSecret;

    public StateTokenAESProvider(AesConfig aesConfig) {
        this.aesSecret = aesConfig.getStateToken();
    }
}