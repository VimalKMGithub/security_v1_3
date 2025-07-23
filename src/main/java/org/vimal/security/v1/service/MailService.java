package org.vimal.security.v1.service;

import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MailService {
    private final RetryableMailService retryableMailService;

    public void sendOtp(String to,
                        String subject,
                        String otp) {
        var text = String.format("""
                Your verification otp is: %s
                This otp will expire in 5 minutes.
                """, otp);
        retryableMailService.sendEmail(to, subject, text);
    }

    @Async
    public void sendOtpAsync(String to,
                             String subject,
                             String otp) {
        sendOtp(to, subject, otp);
    }

    public void sendLinkEmail(String to,
                              String subject,
                              String link) {
        var text = String.format("""
                Your verification link is: %s
                This link will expire in 5 minutes.
                """, link);
        retryableMailService.sendEmail(to, subject, text);
    }

    @Async
    public void sendLinkEmailAsync(String to,
                                   String subject,
                                   String link) {
        sendLinkEmail(to, subject, link);
    }
}