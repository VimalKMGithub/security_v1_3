package org.vimal.security.v1.exception;

public class BadRequestExc extends RuntimeException {
    public BadRequestExc(String message) {
        super(message);
    }
}