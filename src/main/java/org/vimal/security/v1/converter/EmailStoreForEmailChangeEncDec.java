package org.vimal.security.v1.converter;

import org.springframework.stereotype.Component;
import org.vimal.security.v1.util.aes.AESOperationType;
import org.vimal.security.v1.util.aes.factory.AESUtilFactory;

@Component
public class EmailStoreForEmailChangeEncDec extends AbstractConverter<String> {
    public EmailStoreForEmailChangeEncDec(AESUtilFactory aesUtilFactory) {
        super(aesUtilFactory, AESOperationType.EMAIL_STORE_EMAIL_CHANGE);
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