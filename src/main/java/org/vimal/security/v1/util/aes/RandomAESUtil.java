package org.vimal.security.v1.util.aes;

import org.vimal.security.v1.util.aes.key.AESKeyProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class RandomAESUtil implements AESInterface {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final SecureRandom secureRandom = new SecureRandom();
    private final SecretKey secretKey;

    public RandomAESUtil(AESKeyProvider aesKeyProvider) {
        this.secretKey = deriveKey(aesKeyProvider.getAesSecret());
    }

    private SecretKey deriveKey(String secret) {
        try {
            var sha256 = MessageDigest.getInstance("SHA-256");
            var keyBytes = sha256.digest(secret.getBytes());
            return new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            throw new RuntimeException("Error occurred while deriving AES key in RandomAESUtil: " + e.getMessage(), e);
        }
    }

    @Override
    public String encrypt(String data) {
        try {
            var iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);
            var cipher = Cipher.getInstance(TRANSFORMATION);
            var gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
            var encryptedBytes = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error occurred while encrypting data in RandomAESUtil: " + e.getMessage(), e);
        }
    }

    @Override
    public String decrypt(String encryptedData) {
        try {
            var parts = encryptedData.split(":");
            var iv = Base64.getDecoder().decode(parts[0]);
            var encryptedBytes = Base64.getDecoder().decode(parts[1]);
            var cipher = Cipher.getInstance(TRANSFORMATION);
            var gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
            return new String(cipher.doFinal(encryptedBytes));
        } catch (Exception e) {
            throw new RuntimeException("Error occurred while decrypting data in RandomAESUtil: " + e.getMessage(), e);
        }
    }
}