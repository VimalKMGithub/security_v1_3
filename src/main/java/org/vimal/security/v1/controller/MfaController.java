package org.vimal.security.v1.controller;

import com.google.zxing.WriterException;
import lombok.RequiredArgsConstructor;
import org.jose4j.lang.JoseException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.vimal.security.v1.service.AuthAppMfaService;
import org.vimal.security.v1.service.AuthService;
import org.vimal.security.v1.service.EmailMfaService;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/mfa")
public class MfaController {
    private final EmailMfaService emailMfaService;
    private final AuthAppMfaService authAppMfaService;
    private final AuthService authService;

    @PostMapping("/enable/email")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> sendOtpToEnableEmailMfa() {
        return ResponseEntity.ok(emailMfaService.sendOtpToEnableEmailMfa());
    }

    @PostMapping("/enable/email/verify")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> verifyOtpToEnableEmailMfa(@RequestParam String otp) {
        return ResponseEntity.ok(emailMfaService.verifyOtpToEnableEmailMfa(otp));
    }

    @PostMapping("/send/email/otp")
    public ResponseEntity<?> sendOtpToVerifyEmailMfa(@RequestParam String stateToken) {
        return ResponseEntity.ok(authService.sendOtpToVerifyEmailMfa(stateToken));
    }

    @PostMapping("/verify/email/otp")
    public ResponseEntity<?> verifyEmailOtp(@RequestParam String otp,
                                            @RequestParam String stateToken) throws JoseException {
        return ResponseEntity.ok(authService.verifyEmailOtp(otp, stateToken));
    }

    @PostMapping("/disable/email")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> disableEmailMfa(@RequestParam String password) {
        return ResponseEntity.ok(emailMfaService.disableEmailMfa(password));
    }

    @PostMapping(path = "/enable/authapp", produces = MediaType.IMAGE_PNG_VALUE)
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> generateQRCodeForAuthApp() throws NoSuchAlgorithmException, IOException, WriterException {
        return ResponseEntity.ok(authAppMfaService.generateQRCodeForAuthApp());
    }

    @PostMapping("/enable/authapp/verify")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> verifyTotpToSetupAuthApp(@RequestParam String totp) throws InvalidKeyException {
        return ResponseEntity.ok(authAppMfaService.verifyTotpToSetupAuthApp(totp));
    }

    @PostMapping("/verify/authapp/otp")
    public ResponseEntity<?> verifyAuthAppOtp(@RequestParam String totp,
                                              @RequestParam String stateToken) throws JoseException, InvalidKeyException {
        return ResponseEntity.ok(authService.verifyAuthAppOtp(totp, stateToken));
    }

    @PostMapping("/disable/authapp")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> disableAuthApp(@RequestParam String password) {
        return ResponseEntity.ok(authAppMfaService.disableAuthApp(password));
    }
}