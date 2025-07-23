package org.vimal.security.v1.service;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v1.converter.*;
import org.vimal.security.v1.dto.*;
import org.vimal.security.v1.exception.BadRequestExc;
import org.vimal.security.v1.model.UserModel;
import org.vimal.security.v1.repo.UserModelRepo;
import org.vimal.security.v1.service.util.CurrentUserUtil;
import org.vimal.security.v1.service.util.InputValidationUtil;
import org.vimal.security.v1.service.util.RealEmailSanitizerUtil;
import org.vimal.security.v1.util.jwt.JwtUtil;
import org.vimal.security.v1.util.mapper.UserMapperUtil;
import org.vimal.security.v1.util.otp.OtpUtil;
import org.vimal.security.v1.util.otp.TOTPUtil;
import org.vimal.security.v1.util.validation.ValidationsUtil;

import java.security.InvalidKeyException;
import java.time.Duration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class UserSelfService {
    private static final long EMAIL_VERIFICATION_EXPIRES_IN_SECONDS = TimeUnit.MINUTES.toSeconds(5);
    private static final String VERIFY_EMAIL_PREFIX = "verify_email:";
    private static final String EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX = "email_verification_token_mapping:";
    private static final String FORGOT_PASSWORD_PREFIX = "forgot_password:";
    private static final String EMAIL_CHANGE_PREFIX = "email_change:";
    private static final String EMAIL_CHANGE_STORE_PREFIX = "email_change_store:";
    private static final String DELETE_ACCOUNT_BY_EMAIL_OTP_PREFIX = "delete_account_by_email_mfa_otp:";
    private final MailService mailService;
    private final TempTokenService tempTokenService;
    private final UserModelRepo userModelRepo;
    private final PasswordEncoder passwordEncoder;
    private final EmailVerificationTokenEncrypterDecrypter emailVerificationTokenEncrypterDecrypter;
    private final EmailVerificationToken2EncrypterDecrypter emailVerificationToken2EncrypterDecrypter;
    private final EmailOtpForForgotPwdEncDec emailOtpForForgotPwdEncDec;
    private final EmailOtpForForgotPwd2EncDec emailOtpForForgotPwd2EncDec;
    private final EmailOtpForEmailChangeEncDec emailOtpForEmailChangeEncDec;
    private final EmailOtpForEmailChange2EncDec emailOtpForEmailChange2EncDec;
    private final EmailStoreForEmailChangeEncDec emailStoreForEmailChangeEncDec;
    private final EmailStoreForEmailChange2EncDec emailStoreForEmailChange2EncDec;
    private final EmailOtpToDeleteAccountEncDec emailOtpToDeleteAccountEncDec;
    private final EmailOtpToDeleteAccount2EncDec emailOtpToDeleteAccount2EncDec;
    private final AuthAppSecretConverter authAppSecretConverter;
    private final JwtUtil jwtUtil;

    public ResponseEntity<?> register(UserRegistrationDto registrationDto) {
        var validationErrors = InputValidationUtil.validateInputs(registrationDto);
        if (!validationErrors.isEmpty())
            return ResponseEntity.badRequest().body(Map.of("invalid_inputs", validationErrors));
        if (userModelRepo.existsByUsername(registrationDto.getUsername()))
            throw new BadRequestExc("Username: '" + registrationDto.getUsername() + "' already taken");
        var realEmail = RealEmailSanitizerUtil.sanitizeRealEmail(registrationDto.getEmail());
        if (userModelRepo.existsByRealEmail(realEmail) || userModelRepo.existsByEmail(registrationDto.getEmail()))
            throw new BadRequestExc("Email: '" + registrationDto.getEmail() + "' already taken");
        var user = createUserFromRegistration(registrationDto, realEmail);
        var verificationToken = generateAndStoreEmailVerificationToken(user);
        var verificationLink = String.format("https://god-level-security.com/verify-email?token=%s", verificationToken);
        mailService.sendLinkEmailAsync(user.getEmail(), "Email Verification after registration", verificationLink);
        return ResponseEntity.ok(
                Map.of(
                        "message", "Registration successful. A link sent to your registered email to verify your email",
                        "user", UserMapperUtil.toSummaryDto(user)
                )
        );
    }

    private UserModel createUserFromRegistration(UserRegistrationDto dto, String realEmail) {
        return userModelRepo.save(UserModel.builder()
                .firstName(dto.getFirstName())
                .middleName(dto.getMiddleName())
                .lastName(dto.getLastName())
                .username(dto.getUsername())
                .email(dto.getEmail())
                .realEmail(realEmail)
                .password(passwordEncoder.encode(dto.getPassword()))
                .createdBy("Self registration")
                .updatedBy("Self registration")
                .build());
    }

    private String generateAndStoreEmailVerificationToken(UserModel user) {
        var userKey = VERIFY_EMAIL_PREFIX + user.getId();
        var encryptedUserKey = emailVerificationTokenEncrypterDecrypter.convertToDatabaseColumn(userKey);
        var existingToken = tempTokenService.retrieveToken(encryptedUserKey);
        if (existingToken.isPresent())
            return emailVerificationToken2EncrypterDecrypter.convertToEntityAttribute(existingToken.get());
        var newEmailVerificationToken = UUID.randomUUID().toString();
        var reverseLookupKeyForEmailVerification = EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX + newEmailVerificationToken;
        var encryptedReverseLookupKey = emailVerificationTokenEncrypterDecrypter.convertToDatabaseColumn(reverseLookupKeyForEmailVerification);
        try {
            var encryptedToken = emailVerificationToken2EncrypterDecrypter.convertToDatabaseColumn(newEmailVerificationToken);
            tempTokenService.storeToken(encryptedUserKey, encryptedToken, Duration.ofSeconds(EMAIL_VERIFICATION_EXPIRES_IN_SECONDS));
            var encryptedUserId = emailVerificationToken2EncrypterDecrypter.convertToDatabaseColumn(user.getId().toString());
            tempTokenService.storeToken(encryptedReverseLookupKey, encryptedUserId, Duration.ofSeconds(EMAIL_VERIFICATION_EXPIRES_IN_SECONDS));
            return newEmailVerificationToken;
        } catch (Exception e) {
            tempTokenService.removeToken(encryptedUserKey);
            tempTokenService.removeToken(encryptedReverseLookupKey);
            throw new RuntimeException("Failed to generate email verification token: " + e.getMessage(), e);
        }
    }

    public Map<String, Object> verifyEmail(String token) {
        try {
            ValidationsUtil.validateUuid(token);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Invalid verification link");
        }
        var encryptedReverseLookupKey = getEncryptedReverseLookupKey(token);
        var userId = getIdByEncryptedReverseLookupKey(encryptedReverseLookupKey);
        var userKey = VERIFY_EMAIL_PREFIX + userId;
        var encryptedUserKey = emailVerificationTokenEncrypterDecrypter.convertToDatabaseColumn(userKey);
        var storedToken = tempTokenService.retrieveToken(encryptedUserKey).orElseThrow(() -> new BadRequestExc("Link expired"));
        var decryptedStoredToken = emailVerificationToken2EncrypterDecrypter.convertToEntityAttribute(storedToken);
        if (!decryptedStoredToken.equals(token)) throw new BadRequestExc("Invalid verification link");
        var user = userModelRepo.findById(UUID.fromString(userId)).orElseThrow(() -> new BadRequestExc("User not found"));
        if (user.isEmailVerified()) throw new BadRequestExc("Registered email is already verified");
        user.setEmailVerified(true);
        user.setUpdatedBy("Self email verification");
        try {
            tempTokenService.removeToken(encryptedUserKey);
            tempTokenService.removeToken(encryptedReverseLookupKey);
        } catch (Exception ignored) {
        }
        return Map.of(
                "message", "Registered email verified successfully",
                "user", UserMapperUtil.toSummaryDto(userModelRepo.save(user)
                )
        );
    }

    private String getEncryptedReverseLookupKey(String token) {
        var reverseLookupKey = EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX + token;
        return emailVerificationTokenEncrypterDecrypter.convertToDatabaseColumn(reverseLookupKey);
    }

    private String getIdByEncryptedReverseLookupKey(String encryptedReverseLookupKey) {
        var encryptedUserId = tempTokenService.retrieveToken(encryptedReverseLookupKey).orElseThrow(() -> new BadRequestExc("Expired verification link"));
        return emailVerificationToken2EncrypterDecrypter.convertToEntityAttribute(encryptedUserId);
    }

    public Map<String, String> resendEmailVerificationByUsername(String username) {
        try {
            ValidationsUtil.validateUsername(username);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("User with username: '" + username + "' not found");
        }
        var user = userModelRepo.findByUsername(username).orElseThrow(() -> new BadRequestExc("User with username: '" + username + "' not found"));
        if (user.isEmailVerified()) throw new BadRequestExc("Registered email is already verified");
        var newToken = generateAndStoreEmailVerificationToken(user);
        var verificationLink = String.format("https://god-level-security.com/verify-email?token=%s", newToken);
        mailService.sendLinkEmailAsync(user.getEmail(), "Resend email verification after registration using username", verificationLink);
        return Map.of("message", "Verification link resent to your registered email");
    }

    public Map<String, String> resendEmailVerificationByEmail(String email) {
        try {
            ValidationsUtil.validateEmail(email);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("User with email: '" + email + "' not found");
        }
        var user = userModelRepo.findByEmail(email).orElseThrow(() -> new BadRequestExc("User with email: '" + email + "' not found"));
        if (user.isEmailVerified()) throw new BadRequestExc("Registered email is already verified");
        var newToken = generateAndStoreEmailVerificationToken(user);
        var verificationLink = String.format("https://god-level-security.com/verify-email?token=%s", newToken);
        mailService.sendLinkEmailAsync(user.getEmail(), "Resend email verification after registration using email", verificationLink);
        return Map.of("message", "Verification link resent to your registered email");
    }

    public ResponseEntity<?> resendEmailVerification(String usernameOrEmail) {
        try {
            ValidationsUtil.validateString(usernameOrEmail, "Username/email");
        } catch (BadRequestExc e) {
            throw new BadRequestExc("User with username/email: '" + usernameOrEmail + "' not found");
        }
        if (ValidationsUtil.EMAIL_PATTERN.matcher(usernameOrEmail).matches())
            return ResponseEntity.ok(resendEmailVerificationByEmail(usernameOrEmail));
        else if (ValidationsUtil.USERNAME_PATTERN.matcher(usernameOrEmail).matches())
            return ResponseEntity.ok(resendEmailVerificationByUsername(usernameOrEmail));
        else throw new BadRequestExc("User with username/email: '" + usernameOrEmail + "' not found");
    }

    public Map<String, String> forgotPasswordByUsername(String username) {
        try {
            ValidationsUtil.validateUsername(username);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("User with username: '" + username + "' not found");
        }
        var user = userModelRepo.findByUsername(username).orElseThrow(() -> new BadRequestExc("User with username: '" + username + "' not found"));
        if (!user.isEmailVerified()) throw new BadRequestExc("Registered email is not verified");
        var otp = generateAndStoreEmailOtpForForgotPassword(user);
        mailService.sendOtpAsync(user.getEmail(), "Otp for password reset using username", otp);
        return Map.of("message", "OTP sent to your registered email for password reset");
    }

    private String generateAndStoreEmailOtpForForgotPassword(UserModel user) {
        var otp = OtpUtil.generateOtp();
        var userKey = FORGOT_PASSWORD_PREFIX + user.getId();
        var encryptedKey = emailOtpForForgotPwdEncDec.convertToDatabaseColumn(userKey);
        var encryptedOtp = emailOtpForForgotPwd2EncDec.convertToDatabaseColumn(otp);
        tempTokenService.storeToken(encryptedKey, encryptedOtp, Duration.ofSeconds(EMAIL_VERIFICATION_EXPIRES_IN_SECONDS));
        return otp;
    }

    public Map<String, String> forgotPasswordByEmail(String email) {
        try {
            ValidationsUtil.validateEmail(email);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("User with email: '" + email + "' not found");
        }
        var user = userModelRepo.findByEmail(email).orElseThrow(() -> new BadRequestExc("User with email: '" + email + "' not found"));
        if (!user.isEmailVerified()) throw new BadRequestExc("Registered email is not verified");
        var otp = generateAndStoreEmailOtpForForgotPassword(user);
        mailService.sendOtpAsync(user.getEmail(), "Otp for password reset using email", otp);
        return Map.of("message", "OTP sent to your registered email for password reset");
    }

    public ResponseEntity<?> forgotPassword(String usernameOrEmail) {
        try {
            ValidationsUtil.validateString(usernameOrEmail, "Username/email");
        } catch (BadRequestExc e) {
            throw new BadRequestExc("User with username/email: '" + usernameOrEmail + "' not found");
        }
        if (ValidationsUtil.EMAIL_PATTERN.matcher(usernameOrEmail).matches())
            return ResponseEntity.ok(forgotPasswordByEmail(usernameOrEmail));
        else if (ValidationsUtil.USERNAME_PATTERN.matcher(usernameOrEmail).matches())
            return ResponseEntity.ok(forgotPasswordByUsername(usernameOrEmail));
        else throw new BadRequestExc("User with username/email: '" + usernameOrEmail + "' not found");
    }

    public ResponseEntity<?> resetPasswordUsingUsername(ResetPwdDto resetPwdDto) {
        var invalidInputs = InputValidationUtil.validateResetPasswordUsingUsername(resetPwdDto);
        if (!invalidInputs.isEmpty()) return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        var user = userModelRepo.findByUsername(resetPwdDto.getUsername()).orElseThrow(() -> new BadRequestExc("User with username: '" + resetPwdDto.getUsername() + "' not found"));
        verifyOtpForForgotPassword(user, resetPwdDto);
        return ResponseEntity.ok(
                Map.of("message", "Password reset successfully")
        );
    }

    private void verifyOtpForForgotPassword(UserModel user, ResetPwdDto resetPwdDto) {
        var userKey = FORGOT_PASSWORD_PREFIX + user.getId();
        var encryptedKey = emailOtpForForgotPwdEncDec.convertToDatabaseColumn(userKey);
        var storedOtp = tempTokenService.retrieveToken(encryptedKey).orElseThrow(() -> new BadRequestExc("Expired OTP"));
        var decryptedStoredOtp = emailOtpForForgotPwd2EncDec.convertToEntityAttribute(storedOtp);
        if (!decryptedStoredOtp.equals(resetPwdDto.getOtp())) throw new BadRequestExc("Invalid OTP");
        user.changePassword(passwordEncoder.encode(resetPwdDto.getPassword()));
        user.setUpdatedBy("Self password reset");
        userModelRepo.save(user);
        try {
            tempTokenService.removeToken(encryptedKey);
        } catch (Exception ignored) {
        }
    }

    public ResponseEntity<?> resetPasswordUsingEmail(ResetPwdDto resetPwdDto) {
        var invalidInputs = InputValidationUtil.validateResetPasswordUsingEmail(resetPwdDto);
        if (!invalidInputs.isEmpty()) return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        var user = userModelRepo.findByEmail(resetPwdDto.getEmail()).orElseThrow(() -> new BadRequestExc("User with email: '" + resetPwdDto.getEmail() + "' not found"));
        verifyOtpForForgotPassword(user, resetPwdDto);
        return ResponseEntity.ok(
                Map.of("message", "Password reset successfully")
        );
    }

    public ResponseEntity<?> resetPassword(ResetPwdDto resetPwdDto) {
        try {
            ValidationsUtil.validateString(resetPwdDto.getUsernameOrEmail(), "Username/email");
        } catch (BadRequestExc e) {
            return ResponseEntity.badRequest().body(Map.of("invalid_inputs", Set.of("User with username/email: '" + resetPwdDto.getUsernameOrEmail() + "' not found")));
        }
        if (ValidationsUtil.EMAIL_PATTERN.matcher(resetPwdDto.getUsernameOrEmail()).matches()) {
            resetPwdDto.setEmail(resetPwdDto.getUsernameOrEmail());
            return resetPasswordUsingEmail(resetPwdDto);
        } else if (ValidationsUtil.USERNAME_PATTERN.matcher(resetPwdDto.getUsernameOrEmail()).matches()) {
            resetPwdDto.setUsername(resetPwdDto.getUsernameOrEmail());
            return resetPasswordUsingUsername(resetPwdDto);
        } else
            return ResponseEntity.badRequest().body(Map.of("invalid_inputs", Set.of("User with username/email: '" + resetPwdDto.getUsernameOrEmail() + "' not found")));
    }

    public ResponseEntity<?> resetPasswordUsingOldPassword(ResetPwdUsingOldPwdDto resetPwdDto) {
        var invalidInputs = new HashSet<String>();
        try {
            ValidationsUtil.validatePassword(resetPwdDto.getOldPassword());
        } catch (BadRequestExc e) {
            invalidInputs.add("Invalid old password");
        }
        try {
            ValidationsUtil.validatePassword(resetPwdDto.getNewPassword());
            if (!resetPwdDto.getNewPassword().equals(resetPwdDto.getConfirmPassword()))
                invalidInputs.add("New password: '" + resetPwdDto.getNewPassword() + "' and confirm password: '" + resetPwdDto.getConfirmPassword() + "' do not match");
        } catch (BadRequestExc e) {
            invalidInputs.add("New " + e.getMessage());
        }
        if (!invalidInputs.isEmpty()) return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        var currentAuthenticatedUserId = CurrentUserUtil.getCurrentAuthenticatedUser().getId();
        var user = userModelRepo.findById(currentAuthenticatedUserId).orElseThrow(() -> new BadRequestExc("User not found"));
        if (!passwordEncoder.matches(resetPwdDto.getOldPassword(), user.getPassword()))
            throw new BadRequestExc("Invalid old password");
        user.changePassword(passwordEncoder.encode(resetPwdDto.getNewPassword()));
        user.setUpdatedBy("Self password reset using old password");
        userModelRepo.save(user);
        return ResponseEntity.ok(
                Map.of("message", "Password reset successfully")
        );
    }

    public Map<String, String> emailChangeRequest(String email) {
        ValidationsUtil.validateEmail(email);
        var user = CurrentUserUtil.getCurrentAuthenticatedUser();
        if (user.getEmail().equalsIgnoreCase(email))
            throw new BadRequestExc("New email: '" + email + "' is same as current email: '" + user.getEmail() + "'");
        var realEmail = RealEmailSanitizerUtil.sanitizeRealEmail(email);
        if (userModelRepo.existsByRealEmail(realEmail) || userModelRepo.existsByEmail(email))
            throw new BadRequestExc("Email: '" + email + "' already taken");
        var otp = generateAndStoreEmailOtpForEmailChange(user);
        storeEmail(user, email);
        mailService.sendOtpAsync(email, "Otp for email change verification", otp);
        return Map.of("message", "OTP sent to your new email for email verification");
    }

    private String generateAndStoreEmailOtpForEmailChange(UserModel user) {
        var otp = OtpUtil.generateOtp();
        var userKey = EMAIL_CHANGE_PREFIX + user.getId();
        var encryptedKey = emailOtpForEmailChangeEncDec.convertToDatabaseColumn(userKey);
        var encryptedOtp = emailOtpForEmailChange2EncDec.convertToDatabaseColumn(otp);
        tempTokenService.storeToken(encryptedKey, encryptedOtp, Duration.ofSeconds(EMAIL_VERIFICATION_EXPIRES_IN_SECONDS));
        return otp;
    }

    private void storeEmail(UserModel user,
                            String email) {
        var userKey = EMAIL_CHANGE_STORE_PREFIX + user.getId();
        var encryptedKey = emailStoreForEmailChangeEncDec.convertToDatabaseColumn(userKey);
        var encryptedEmail = emailStoreForEmailChange2EncDec.convertToDatabaseColumn(email);
        tempTokenService.storeToken(encryptedKey, encryptedEmail, Duration.ofSeconds(EMAIL_VERIFICATION_EXPIRES_IN_SECONDS));
    }

    public ResponseEntity<?> verifyEmailChange(String otp,
                                               String password) {
        try {
            ValidationsUtil.validateOtpTotp(otp);
            ValidationsUtil.validatePassword(password);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Invalid otp or password");
        }
        var user = CurrentUserUtil.getCurrentAuthenticatedUser();
        var userKey = EMAIL_CHANGE_PREFIX + user.getId();
        var encryptedKey = emailOtpForEmailChangeEncDec.convertToDatabaseColumn(userKey);
        var storedOtp = tempTokenService.retrieveToken(encryptedKey).orElseThrow(() -> new BadRequestExc("Expired otp"));
        var decryptedStoredOtp = emailOtpForEmailChange2EncDec.convertToEntityAttribute(storedOtp);
        if (!decryptedStoredOtp.equals(otp)) throw new BadRequestExc("Invalid otp");
        var encryptedEmailKey = EMAIL_CHANGE_STORE_PREFIX + user.getId();
        var encryptedEmail = emailStoreForEmailChangeEncDec.convertToDatabaseColumn(encryptedEmailKey);
        var newEmail = tempTokenService.retrieveToken(encryptedEmail).orElseThrow(() -> new BadRequestExc("Request expired"));
        var decryptedNewEmail = emailStoreForEmailChange2EncDec.convertToEntityAttribute(newEmail);
        var realEmail = RealEmailSanitizerUtil.sanitizeRealEmail(decryptedNewEmail);
        if (userModelRepo.existsByRealEmail(realEmail)) throw new BadRequestExc("Requested email is already taken");
        user = userModelRepo.findById(user.getId()).orElseThrow(() -> new BadRequestExc("User not found"));
        if (!passwordEncoder.matches(password, user.getPassword())) throw new BadRequestExc("Invalid password");
        user.setEmail(decryptedNewEmail);
        user.setRealEmail(realEmail);
        user.setUpdatedBy("Self email change");
        try {
            tempTokenService.removeToken(encryptedKey);
            tempTokenService.removeToken(encryptedEmail);
        } catch (Exception ignored) {
        }
        jwtUtil.revokeAccessToken(user);
        jwtUtil.revokeRefreshTokenByUser(user);
        return ResponseEntity.ok(
                Map.of(
                        "message", "Your email changed successfully to: '" + decryptedNewEmail + "'. Please login again to continue",
                        "user", UserMapperUtil.toSummaryDto(userModelRepo.save(user))
                )
        );
    }

    public UserSummaryDto getYourself() {
        var currentAuthenticatedUserId = CurrentUserUtil.getCurrentAuthenticatedUser().getId();
        var user = userModelRepo.findById(currentAuthenticatedUserId).orElseThrow(() -> new BadRequestExc("User not found"));
        return UserMapperUtil.toSummaryDto(user);
    }

    public Map<String, String> deleteAccountByPassword(String password) {
        try {
            ValidationsUtil.validatePassword(password);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Invalid password");
        }
        var user = CurrentUserUtil.getCurrentAuthenticatedUser();
        if (user.isMfaEnabled() && !user.getEnabledMfaMethods().isEmpty())
            throw new BadRequestExc("Mfa: " + user.getEnabledMfaMethods() + " is/are enabled. You cannot delete your mfa enabled account using password only");
        user = userModelRepo.findById(user.getId()).orElseThrow(() -> new BadRequestExc("User not found"));
        if (!passwordEncoder.matches(password, user.getPassword())) throw new BadRequestExc("Invalid password");
        jwtUtil.revokeAccessToken(user);
        jwtUtil.revokeRefreshTokenByUser(user);
        userModelRepo.delete(user);
        return Map.of("message", "Account deleted successfully");
    }

    public Map<String, String> sendEmailOtpToDeleteAccount() {
        var user = CurrentUserUtil.getCurrentAuthenticatedUser();
        if (!user.hasMfaEnabled(UserModel.MfaType.EMAIL)) throw new BadRequestExc("Email Mfa is not enabled");
        var otp = generateAndStoreEmailOtpToDeleteUser(user);
        mailService.sendOtpAsync(user.getEmail(), "Otp for account deletion email mfa", otp);
        return Map.of("message", "OTP sent to your registered email for account deletion verification");
    }

    private String generateAndStoreEmailOtpToDeleteUser(UserModel user) {
        var otp = OtpUtil.generateOtp();
        var userKey = DELETE_ACCOUNT_BY_EMAIL_OTP_PREFIX + user.getId();
        var encryptedKey = emailOtpToDeleteAccountEncDec.convertToDatabaseColumn(userKey);
        var encryptedOtp = emailOtpToDeleteAccount2EncDec.convertToDatabaseColumn(otp);
        tempTokenService.storeToken(encryptedKey, encryptedOtp, Duration.ofSeconds(EMAIL_VERIFICATION_EXPIRES_IN_SECONDS));
        return otp;
    }

    public Map<String, String> verifyEmailOtpToDeleteAccount(String password,
                                                             String otp) {
        try {
            ValidationsUtil.validatePassword(password);
            ValidationsUtil.validateOtpTotp(otp);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Invalid password or otp");
        }
        var user = CurrentUserUtil.getCurrentAuthenticatedUser();
        if (!user.hasMfaEnabled(UserModel.MfaType.EMAIL)) throw new BadRequestExc("Email Mfa is not enabled");
        var userKey = DELETE_ACCOUNT_BY_EMAIL_OTP_PREFIX + user.getId();
        var encryptedKey = emailOtpToDeleteAccountEncDec.convertToDatabaseColumn(userKey);
        var storedOtp = tempTokenService.retrieveToken(encryptedKey).orElseThrow(() -> new BadRequestExc("Expired OTP"));
        var decryptedStoredOtp = emailOtpToDeleteAccount2EncDec.convertToEntityAttribute(storedOtp);
        if (!decryptedStoredOtp.equals(otp)) throw new BadRequestExc("Invalid OTP");
        user = userModelRepo.findById(user.getId()).orElseThrow(() -> new BadRequestExc("User not found"));
        if (!passwordEncoder.matches(password, user.getPassword())) throw new BadRequestExc("Invalid password");
        try {
            tempTokenService.removeToken(encryptedKey);
        } catch (Exception ignored) {
        }
        jwtUtil.revokeAccessToken(user);
        jwtUtil.revokeRefreshTokenByUser(user);
        userModelRepo.delete(user);
        return Map.of("message", "Account deleted successfully");
    }

    public ResponseEntity<?> deleteAccountByAuthAppTotp(String password,
                                                        String totp) throws InvalidKeyException {
        try {
            ValidationsUtil.validatePassword(password);
            ValidationsUtil.validateOtpTotp(totp);
        } catch (BadRequestExc e) {
            throw new BadRequestExc("Invalid password or TOTP");
        }
        var user = CurrentUserUtil.getCurrentAuthenticatedUser();
        if (!user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
            throw new BadRequestExc("Authenticator App Mfa is not enabled");
        user = userModelRepo.findById(user.getId()).orElseThrow(() -> new BadRequestExc("User not found"));
        if (!TOTPUtil.verifyOTP(authAppSecretConverter.convertToEntityAttribute(user.getAuthAppSecret()), totp))
            throw new BadRequestExc("Invalid TOTP");
        if (!passwordEncoder.matches(password, user.getPassword())) throw new BadRequestExc("Invalid password");
        jwtUtil.revokeAccessToken(user);
        jwtUtil.revokeRefreshTokenByUser(user);
        userModelRepo.delete(user);
        return ResponseEntity.ok(
                Map.of("message", "Account deleted successfully")
        );
    }

    public ResponseEntity<?> updateYourselfBasic(UserSelfUpdationDto request) {
        var currentAuthenticatedUserId = CurrentUserUtil.getCurrentAuthenticatedUser().getId();
        var user = userModelRepo.findById(currentAuthenticatedUserId).orElseThrow(() -> new BadRequestExc("User not found"));
        var invalidInputs = new HashSet<String>();
        var isUpdated = false;
        var shouldRemoveTokens = false;
        try {
            ValidationsUtil.validateString(request.getOldPassword(), "Old password");
            if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword()))
                invalidInputs.add("Invalid old password");
        } catch (BadRequestExc e) {
            invalidInputs.add("Invalid old password");
        }
        if (request.getFirstName() != null && !request.getFirstName().equals(user.getFirstName())) {
            try {
                ValidationsUtil.validateFirstName(request.getFirstName());
                user.setFirstName(request.getFirstName());
                isUpdated = true;
            } catch (BadRequestExc e) {
                invalidInputs.add(e.getMessage());
            }
        }
        if (request.getMiddleName() != null && !request.getMiddleName().equals(user.getMiddleName())) {
            try {
                ValidationsUtil.validateMiddleName(request.getMiddleName());
                user.setMiddleName(request.getMiddleName());
                isUpdated = true;
            } catch (BadRequestExc e) {
                invalidInputs.add(e.getMessage());
            }
        }
        if (request.getLastName() != null && !request.getLastName().equals(user.getLastName())) {
            try {
                ValidationsUtil.validateLastName(request.getLastName());
                user.setLastName(request.getLastName());
                isUpdated = true;
            } catch (BadRequestExc e) {
                invalidInputs.add(e.getMessage());
            }
        }
        if (request.getNewPassword() != null) {
            try {
                ValidationsUtil.validatePassword(request.getNewPassword());
                if (!request.getNewPassword().equals(request.getConfirmNewPassword()))
                    invalidInputs.add("New password: '" + request.getNewPassword() + "' and confirm new password: '" + request.getConfirmNewPassword() + "' do not match");
                else {
                    user.changePassword(passwordEncoder.encode(request.getNewPassword()));
                    isUpdated = true;
                }
            } catch (BadRequestExc e) {
                invalidInputs.add("New " + e.getMessage());
            }
        }
        if (request.getUsername() != null && !request.getUsername().equals(user.getUsername())) {
            try {
                ValidationsUtil.validateUsername(request.getUsername());
                if (userModelRepo.existsByUsername(request.getUsername()))
                    invalidInputs.add("Username: '" + request.getUsername() + "' is already taken");
                else {
                    user.setUsername(request.getUsername());
                    isUpdated = true;
                    shouldRemoveTokens = true;
                }
            } catch (BadRequestExc e) {
                invalidInputs.add(e.getMessage());
            }
        }
        if (!invalidInputs.isEmpty()) return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        if (!isUpdated) return ResponseEntity.ok(Map.of("message", "No changes made to your account"));
        else {
            if (shouldRemoveTokens) {
                jwtUtil.revokeAccessToken(user);
                jwtUtil.revokeRefreshTokenByUser(user);
            }
            user.setUpdatedBy("Self update basic info");
            return ResponseEntity.ok(
                    userModelRepo.save(user)
            );
        }
    }
}