package org.vimal.security.v1.util.otp;

import org.vimal.security.v1.exception.BadRequestExc;

import java.security.SecureRandom;

public final class OtpUtil {
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final String DIGITS = "0123456789";
    private static final int DEFAULT_OTP_LENGTH = 6;

    private OtpUtil() {
        throw new AssertionError("Cannot instantiate OtpUtil class");
    }

    public static String generateOtp() {
        return generateOtp(DEFAULT_OTP_LENGTH);
    }

    public static String generateOtp(int length) {
        if (length < 1) throw new BadRequestExc("OTP length must be at least 1");
        var otpChars = new char[length];
        for (int i = 0; i < length; i++) otpChars[i] = DIGITS.charAt(secureRandom.nextInt(DIGITS.length()));
        return new String(otpChars);
    }
}