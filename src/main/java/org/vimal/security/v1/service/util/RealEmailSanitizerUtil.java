package org.vimal.security.v1.service.util;

import java.util.Set;

public final class RealEmailSanitizerUtil {
    private RealEmailSanitizerUtil() {
        throw new AssertionError("Cannot instantiate RealEmailSanitizerUtil class");
    }

    private static final Set<String> SANITIZE_DOTS = Set.of("gmail.com", "googlemail.com");
    private static final Set<String> SANITIZE_PLUS = Set.of("gmail.com", "googlemail.com", "live.com", "protonmail.com", "hotmail.com", "outlook.com");

    public static String sanitizeRealEmail(String realEmail) {
        var lowerCased = realEmail.trim().toLowerCase();
        var atIndex = lowerCased.indexOf('@');
        var localPart = lowerCased.substring(0, atIndex);
        var domainPart = lowerCased.substring(atIndex + 1);
        if (SANITIZE_DOTS.contains(domainPart)) {
            localPart = localPart.replace(".", "");
        }
        if (SANITIZE_PLUS.contains(domainPart)) {
            var plusIndex = localPart.indexOf('+');
            if (plusIndex != -1) {
                localPart = localPart.substring(0, plusIndex);
            }
        }
        return localPart + "@" + domainPart;
    }
}