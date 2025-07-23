package org.vimal.security.v1.util.aes;

import org.vimal.security.v1.util.aes.key.AESKeyProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Base64;

public class DeterministicAESUtil implements AESInterface {
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final byte[] FIXED_IV = new byte[16];
    private final SecretKey secretKey;

    public DeterministicAESUtil(AESKeyProvider aesKeyProvider) {
        this.secretKey = deriveKey(aesKeyProvider.getAesSecret());
    }

    private SecretKey deriveKey(String secret) {
        try {
            var sha256 = MessageDigest.getInstance("SHA-256");
            var keyBytes = sha256.digest(secret.getBytes());
            return new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            throw new RuntimeException("Error occurred while deriving AES key in DeterministicAESUtil: " + e.getMessage(), e);
        }
    }

    @Override
    public String encrypt(String data) {
        try {
            var cipher = Cipher.getInstance(TRANSFORMATION);
            var ivSpec = new IvParameterSpec(FIXED_IV);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            var encryptedBytes = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error occurred while encrypting data in DeterministicAESUtil: " + e.getMessage(), e);
        }
    }

    @Override
    public String decrypt(String encryptedData) {
        try {
            var cipher = Cipher.getInstance(TRANSFORMATION);
            var ivSpec = new IvParameterSpec(FIXED_IV);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            var decodedBytes = Base64.getDecoder().decode(encryptedData);
            return new String(cipher.doFinal(decodedBytes));
        } catch (Exception e) {
            throw new RuntimeException("Error occurred while decrypting data in DeterministicAESUtil: " + e.getMessage(), e);
        }
    }
}