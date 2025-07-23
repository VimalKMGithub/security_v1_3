package org.vimal.security.v1.util.aes;

public interface AESInterface {
    String encrypt(String data);

    String decrypt(String data);
}