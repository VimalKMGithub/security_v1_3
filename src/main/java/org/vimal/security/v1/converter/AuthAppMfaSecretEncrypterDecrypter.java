package org.vimal.security.v1.converter;

import org.springframework.stereotype.Component;
import org.vimal.security.v1.util.aes.AESOperationType;
import org.vimal.security.v1.util.aes.factory.AESUtilFactory;

@Component
public class AuthAppMfaSecretEncrypterDecrypter extends AbstractConverter<String> {
    public AuthAppMfaSecretEncrypterDecrypter(AESUtilFactory aesUtilFactory) {
        super(aesUtilFactory, AESOperationType.AUTH_APP_MFA_SECRET);
    }

    @Override
    protected String toString(String attribute) {
        return attribute;
    }

    @Override
    protected String fromString(String dbData) {
        return dbData;
    }
}