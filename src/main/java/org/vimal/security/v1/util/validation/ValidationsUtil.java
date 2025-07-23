package org.vimal.security.v1.util.validation;

import org.vimal.security.v1.exception.BadRequestExc;

import java.util.regex.Pattern;

public final class ValidationsUtil {
    public static final Pattern EMAIL_PATTERN = Pattern.compile("^(?=.{1,64}@)[\\p{L}0-9]+([._+-][\\p{L}0-9]+)*@([\\p{L}0-9]+(-[\\p{L}0-9]+)*\\.)+\\p{L}{2,190}$");
    public static final Pattern USERNAME_PATTERN = Pattern.compile("^[\\p{L}0-9_-]{3,100}$");
    public static final Pattern PASSWORD_PATTERN = Pattern.compile("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]).{8,255}$");
    public static final Pattern NAME_PATTERN = Pattern.compile("^[\\p{L} .'-]+$");
    public static final Pattern ROLE_AND_PERMISSION_NAME_PATTERN = Pattern.compile("^[\\p{L}0-9_]+$");
    public static final Pattern UUID_PATTERN = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$");
    public static final Pattern NUMBER_ONLY_PATTERN = Pattern.compile("^[0-9]+$");

    private ValidationsUtil() {
        throw new AssertionError("Cannot instantiate ValidationsUtil class");
    }

    public static void validateFirstName(String firstName) {
        validateString(firstName, "First name", 50);
        if (!NAME_PATTERN.matcher(firstName).matches())
            throw new BadRequestExc("First name: '" + firstName + "' is invalid as first name can only contain letters, spaces, hyphens, and apostrophes");
    }

    public static void validateMiddleName(String middleName) {
        if (middleName == null) return;
        validateString(middleName, "Middle name", 50);
        if (!NAME_PATTERN.matcher(middleName).matches())
            throw new BadRequestExc("Middle name: '" + middleName + "' is invalid as middle name can only contain letters, spaces, hyphens, and apostrophes");
    }

    public static void validateLastName(String lastName) {
        if (lastName == null) return;
        validateString(lastName, "Last name", 50);
        if (!NAME_PATTERN.matcher(lastName).matches())
            throw new BadRequestExc("Last name: '" + lastName + "' is invalid as last name can only contain letters, spaces, hyphens, and apostrophes");
    }

    public static void validateEmail(String email) {
        validateString(email, "Email", 254);
        if (!EMAIL_PATTERN.matcher(email).matches())
            throw new BadRequestExc("Email: '" + email + "' is of invalid format");
    }

    public static void validateUsername(String username) {
        validateString(username, "Username", 3, 100);
        if (!USERNAME_PATTERN.matcher(username).matches())
            throw new BadRequestExc("Username: '" + username + "' is invalid as username can only contain letters, numbers, underscores, and hyphens");
    }

    public static void validatePassword(String password) {
        validateString(password, "Password", 8, 255);
        if (!PASSWORD_PATTERN.matcher(password).matches())
            throw new BadRequestExc("Password: '" + password + "' is invalid as password must contain at least one digit, one lowercase letter, one uppercase letter, and one special character");
    }

    public static void validateRoleName(String roleName) {
        validateString(roleName, "Role name", 50);
        if (!ROLE_AND_PERMISSION_NAME_PATTERN.matcher(roleName).matches())
            throw new BadRequestExc("Role name: '" + roleName + "' is invalid as role name can only contain letters, numbers, and underscores");
    }

    public static void validatePermissionName(String permissionName) {
        validateString(permissionName, "Permission name", 100);
        if (!ROLE_AND_PERMISSION_NAME_PATTERN.matcher(permissionName).matches())
            throw new BadRequestExc("Permission name: '" + permissionName + "' is invalid as permission name can only contain letters, numbers, and underscores");
    }

    public static void validateUuid(String uuid) {
        validateUuid(uuid, "UUID");
    }

    public static void validateUuid(String uuid,
                                    String fieldName) {
        validateString(uuid, fieldName);
        if (!UUID_PATTERN.matcher(uuid).matches())
            throw new BadRequestExc(fieldName + ": '" + uuid + "' is of invalid format");
    }

    public static void validateOtpTotp(String otpTotp) {
        validateOtpTotp(otpTotp, 6);
    }

    public static void validateOtpTotp(String otpTotp,
                                       int exactLength) {
        validateStringExactLength(otpTotp, "OTP/TOTP", exactLength);
        if (!NUMBER_ONLY_PATTERN.matcher(otpTotp).matches())
            throw new BadRequestExc("OTP/TOTP: '" + otpTotp + "' can only contain numbers");
    }

    public static void validateDescription(String description) {
        if (description == null) return;
        validateString(description, "Description", 255);
    }

    public static void validateString(String value,
                                      String fieldName) {
        if (value == null)
            throw new BadRequestExc(fieldName + ": '" + null + "' is null but " + fieldName + " cannot be null");
        if (value.isBlank())
            throw new BadRequestExc(fieldName + ": '" + value + "' is blank but " + fieldName + " cannot be blank");
    }

    public static void validateStringExactLength(String value,
                                                 String fieldName,
                                                 int exactLength) {
        validateString(value, fieldName);
        if (value.length() != exactLength)
            throw new BadRequestExc(fieldName + ": '" + value + "' must be exactly " + exactLength + " characters long");
    }

    public static void validateString(String value,
                                      String fieldName,
                                      int characterLimitMax) {
        validateString(value, fieldName, 1, characterLimitMax);
    }

    public static void validateString(String value,
                                      String fieldName,
                                      int characterLimitMin,
                                      int characterLimitMax) {
        validateString(value, fieldName);
        if (value.length() < characterLimitMin)
            throw new BadRequestExc(fieldName + ": '" + value + "' is too short, must be at least " + characterLimitMin + " characters");
        if (value.length() > characterLimitMax)
            throw new BadRequestExc(fieldName + ": '" + value + "' exceeds maximum length of " + characterLimitMin + " characters");
    }
}