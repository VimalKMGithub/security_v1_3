package org.vimal.security.v1.security;

public class SecurityConstants {
    public static final String API_VERSION = "/api/v1";
    public static final String USER_SELF = "/user/self";
    public static final String AUTH = "/auth";
    public static final String MFA = "/mfa";

    public static final String[] WHITELIST = {
            API_VERSION + AUTH + "/login-by-username",
            API_VERSION + AUTH + "/login-by-email",
            API_VERSION + AUTH + "/login",
            API_VERSION + AUTH + "/refresh-access-token",
            API_VERSION + AUTH + "/revoke-refresh-token",

            API_VERSION + USER_SELF + "/register",
            API_VERSION + USER_SELF + "/verify-email",
            API_VERSION + USER_SELF + "/resend-email-verification-by-username",
            API_VERSION + USER_SELF + "/resend-email-verification-by-email",
            API_VERSION + USER_SELF + "/resend-email-verification",
            API_VERSION + USER_SELF + "/forgot-password-by-username",
            API_VERSION + USER_SELF + "/forgot-password-by-email",
            API_VERSION + USER_SELF + "/forgot-password",
            API_VERSION + USER_SELF + "/reset-password-using-username",
            API_VERSION + USER_SELF + "/reset-password-using-email",
            API_VERSION + USER_SELF + "/reset-password",

            API_VERSION + MFA + "/send/email/otp",
            API_VERSION + MFA + "/verify/email/otp",
            API_VERSION + MFA + "/verify/authapp/otp"
    };
}