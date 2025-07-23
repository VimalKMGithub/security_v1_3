package org.vimal.security.v1.converter;

import jakarta.persistence.AttributeConverter;
import org.vimal.security.v1.util.aes.AESInterface;
import org.vimal.security.v1.util.aes.AESOperationType;
import org.vimal.security.v1.util.aes.factory.AESUtilFactory;

public abstract class AbstractConverter<T> implements AttributeConverter<T, String> {
    private final AESInterface aesUtil;

    protected AbstractConverter(AESUtilFactory aesUtilFactory,
                                AESOperationType operationType) {
        this.aesUtil = aesUtilFactory.getUtil(operationType);
    }

    protected abstract String toString(T attribute);

    protected abstract T fromString(String dbData);

    @Override
    public String convertToDatabaseColumn(T attribute) {
        if (attribute == null) return null;
        String stringValue = toString(attribute);
        return aesUtil.encrypt(stringValue);
    }

    @Override
    public T convertToEntityAttribute(String dbData) {
        if (dbData == null) return null;
        String decrypted = aesUtil.decrypt(dbData);
        return fromString(decrypted);
    }
}