package org.vimal.security.v1.converter;

import org.springframework.stereotype.Component;
import org.vimal.security.v1.util.aes.AESOperationType;
import org.vimal.security.v1.util.aes.factory.AESUtilFactory;

@Component
public class EmailOtpForMfa2EncrypterDecrypter extends AbstractConverter<String> {
    public EmailOtpForMfa2EncrypterDecrypter(AESUtilFactory aesUtilFactory) {
        super(aesUtilFactory, AESOperationType.EMAIL_OTP_FOR_MFA_2);
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