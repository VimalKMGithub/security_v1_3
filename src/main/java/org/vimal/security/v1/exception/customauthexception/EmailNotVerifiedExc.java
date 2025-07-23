package org.vimal.security.v1.exception.customauthexception;

import org.springframework.security.core.AuthenticationException;

public class EmailNotVerifiedExc extends AuthenticationException {
    public EmailNotVerifiedExc(String message) {
        super(message);
    }
}