package org.vimal.security.v1.converter;

import org.springframework.stereotype.Component;
import org.vimal.security.v1.util.aes.AESOperationType;
import org.vimal.security.v1.util.aes.factory.AESUtilFactory;

@Component
public class EmailStoreForEmailChange2EncDec extends AbstractConverter<String> {
    public EmailStoreForEmailChange2EncDec(AESUtilFactory aesUtilFactory) {
        super(aesUtilFactory, AESOperationType.EMAIL_STORE_EMAIL_CHANGE_2);
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