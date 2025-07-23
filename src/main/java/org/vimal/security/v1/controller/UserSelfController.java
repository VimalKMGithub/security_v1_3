package org.vimal.security.v1.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.vimal.security.v1.dto.ResetPwdDto;
import org.vimal.security.v1.dto.ResetPwdUsingOldPwdDto;
import org.vimal.security.v1.dto.UserRegistrationDto;
import org.vimal.security.v1.dto.UserSelfUpdationDto;
import org.vimal.security.v1.service.UserSelfService;

import java.security.InvalidKeyException;

@RestController
@RequestMapping("/api/v1/user/self")
@RequiredArgsConstructor
public class UserSelfController {
    private final UserSelfService userSelfService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody UserRegistrationDto registrationDto) {
        return userSelfService.register(registrationDto);
    }

    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam String token) {
        return ResponseEntity.ok(userSelfService.verifyEmail(token));
    }

    @PostMapping("/resend-email-verification-by-username")
    public ResponseEntity<?> resendEmailVerificationByUsername(@RequestParam String username) {
        return ResponseEntity.ok(userSelfService.resendEmailVerificationByUsername(username));
    }

    @PostMapping("/resend-email-verification-by-email")
    public ResponseEntity<?> resendEmailVerificationByEmail(@RequestParam String email) {
        return ResponseEntity.ok(userSelfService.resendEmailVerificationByEmail(email));
    }

    @PostMapping("/resend-email-verification")
    public ResponseEntity<?> resendEmailVerification(@RequestParam String usernameOrEmail) {
        return userSelfService.resendEmailVerification(usernameOrEmail);
    }

    @PostMapping("/forgot-password-by-username")
    public ResponseEntity<?> forgotPasswordByUsername(@RequestParam String username) {
        return ResponseEntity.ok(userSelfService.forgotPasswordByUsername(username));
    }

    @PostMapping("/forgot-password-by-email")
    public ResponseEntity<?> forgotPasswordByEmail(@RequestParam String email) {
        return ResponseEntity.ok(userSelfService.forgotPasswordByEmail(email));
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String usernameOrEmail) {
        return userSelfService.forgotPassword(usernameOrEmail);
    }

    @PostMapping("/reset-password-using-username")
    public ResponseEntity<?> resetPasswordUsingUsername(@RequestBody ResetPwdDto resetPwdDto) {
        return userSelfService.resetPasswordUsingUsername(resetPwdDto);
    }

    @PostMapping("/reset-password-using-email")
    public ResponseEntity<?> resetPasswordUsingEmail(@RequestBody ResetPwdDto resetPwdDto) {
        return userSelfService.resetPasswordUsingEmail(resetPwdDto);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPwdDto resetPwdDto) {
        return userSelfService.resetPassword(resetPwdDto);
    }

    @PostMapping("/reset-password-using-old-password")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> resetPasswordUsingOldPassword(@RequestBody ResetPwdUsingOldPwdDto resetPwdDto) {
        return userSelfService.resetPasswordUsingOldPassword(resetPwdDto);
    }

    @PostMapping("/email-change-request")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> emailChangeRequest(@RequestParam String email) {
        return ResponseEntity.ok(userSelfService.emailChangeRequest(email));
    }

    @PostMapping("/verify-email-change")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> verifyEmailChange(@RequestParam String otp,
                                               @RequestParam String password) {
        return userSelfService.verifyEmailChange(otp, password);
    }

    @GetMapping("/get-yourself")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getYourself() {
        return ResponseEntity.ok(userSelfService.getYourself());
    }

    @DeleteMapping("/delete-account-by-password")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> deleteAccountByPassword(@RequestParam String password) {
        return ResponseEntity.ok(userSelfService.deleteAccountByPassword(password));
    }

    @PostMapping("/send-email-otp-to-delete-account")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> sendEmailOtpToDeleteAccount() {
        return ResponseEntity.ok(userSelfService.sendEmailOtpToDeleteAccount());
    }

    @DeleteMapping("/verify-email-otp-to-delete-account")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> verifyEmailOtpToDeleteAccount(@RequestParam String password,
                                                           @RequestParam String otp) {
        return ResponseEntity.ok(userSelfService.verifyEmailOtpToDeleteAccount(password, otp));
    }

    @DeleteMapping("/delete-account-by-auth-app-totp")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> deleteAccountByAuthAppTotp(@RequestParam String password,
                                                        @RequestParam String totp) throws InvalidKeyException {
        return userSelfService.deleteAccountByAuthAppTotp(password, totp);
    }

    @PutMapping("/update-yourself-basic")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> updateYourselfBasic(@RequestBody UserSelfUpdationDto request) {
        return userSelfService.updateYourselfBasic(request);
    }
}