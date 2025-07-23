package org.vimal.security.v1.exception.customauthexception;

import org.springframework.security.core.AuthenticationException;

public class CustomLockedExc extends AuthenticationException {
    public CustomLockedExc(String message) {
        super(message);
    }
}