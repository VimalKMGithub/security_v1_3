package org.vimal.security.v1.service.util;

import org.vimal.security.v1.dto.ResetPwdDto;
import org.vimal.security.v1.dto.RoleCreationDto;
import org.vimal.security.v1.dto.UserCreationDto;
import org.vimal.security.v1.dto.UserRegistrationDto;
import org.vimal.security.v1.exception.BadRequestExc;
import org.vimal.security.v1.util.validation.ValidationsUtil;

import java.util.HashSet;
import java.util.Set;

public final class InputValidationUtil {
    private InputValidationUtil() {
        throw new AssertionError("Cannot instantiate InputValidationUtil class");
    }

    public static Set<String> validateInputs(UserRegistrationDto dto) {
        return validateInputs(
                dto.getUsername(),
                dto.getPassword(),
                dto.getEmail(),
                dto.getFirstName(),
                dto.getMiddleName(),
                dto.getLastName()
        );
    }

    public static Set<String> validateInputs(UserCreationDto dto) {
        return validateInputs(
                dto.getUsername(),
                dto.getPassword(),
                dto.getEmail(),
                dto.getFirstName(),
                dto.getMiddleName(),
                dto.getLastName()
        );
    }

    public static Set<String> validateInputs(String username,
                                             String password,
                                             String email,
                                             String firstName,
                                             String middleName,
                                             String lastName) {
        var validationErrors = new HashSet<String>();
        try {
            ValidationsUtil.validateUsername(username);
        } catch (BadRequestExc e) {
            validationErrors.add(e.getMessage());
        }
        try {
            ValidationsUtil.validatePassword(password);
        } catch (BadRequestExc e) {
            validationErrors.add(e.getMessage());
        }
        try {
            ValidationsUtil.validateEmail(email);
        } catch (BadRequestExc e) {
            validationErrors.add(e.getMessage());
        }
        try {
            ValidationsUtil.validateFirstName(firstName);
        } catch (BadRequestExc e) {
            validationErrors.add(e.getMessage());
        }
        try {
            ValidationsUtil.validateMiddleName(middleName);
        } catch (BadRequestExc e) {
            validationErrors.add(e.getMessage());
        }
        try {
            ValidationsUtil.validateLastName(lastName);
        } catch (BadRequestExc e) {
            validationErrors.add(e.getMessage());
        }
        return validationErrors;
    }

    public static Set<String> validateResetPasswordUsingUsername(ResetPwdDto dto) {
        var validationErrors = validateResetPasswordCommonFields(dto);
        try {
            ValidationsUtil.validateUsername(dto.getUsername());
        } catch (BadRequestExc e) {
            validationErrors.add("User with username: '" + dto.getUsername() + "' not found");
        }
        return validationErrors;
    }

    public static Set<String> validateResetPasswordUsingEmail(ResetPwdDto dto) {
        var validationErrors = validateResetPasswordCommonFields(dto);
        try {
            ValidationsUtil.validateEmail(dto.getEmail());
        } catch (BadRequestExc e) {
            validationErrors.add("User with email: '" + dto.getEmail() + "' not found");
        }
        return validationErrors;
    }

    public static Set<String> validateResetPasswordCommonFields(ResetPwdDto dto) {
        var validationErrors = new HashSet<String>();
        try {
            ValidationsUtil.validatePassword(dto.getPassword());
            if (!dto.getPassword().equals(dto.getConfirmPassword()))
                validationErrors.add("New password: '" + dto.getPassword() + "' and confirm password: '" + dto.getConfirmPassword() + "' do not match");
        } catch (BadRequestExc e) {
            validationErrors.add("New " + e.getMessage());
        }
        try {
            ValidationsUtil.validateOtpTotp(dto.getOtp());
        } catch (BadRequestExc e) {
            validationErrors.add("Invalid OTP");
        }
        return validationErrors;
    }

    public static Set<String> validateInputs(RoleCreationDto dto) {
        var validationErrors = new HashSet<String>();
        try {
            ValidationsUtil.validateRoleName(dto.getRoleName());
        } catch (BadRequestExc e) {
            validationErrors.add(e.getMessage());
        }
        try {
            ValidationsUtil.validateDescription(dto.getDescription());
        } catch (BadRequestExc e) {
            validationErrors.add(e.getMessage());
        }
        return validationErrors;
    }
}