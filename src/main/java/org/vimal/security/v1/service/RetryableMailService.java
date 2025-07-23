package org.vimal.security.v1.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Recover;
import org.springframework.retry.annotation.Retryable;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class RetryableMailService {
    private final JavaMailSender mailSender;
    private final String fromDisplayName;
    private final String helpMailAddress;

    public RetryableMailService(JavaMailSender mailSender,
                                @Value("${app.mail.from-display-name}") String fromDisplayName,
                                @Value("${app.help.mail.address}") String helpMailAddress) {
        this.mailSender = mailSender;
        this.fromDisplayName = fromDisplayName;
        this.helpMailAddress = helpMailAddress;
    }

    @Retryable(
            retryFor = Exception.class,
            maxAttempts = 5,
            backoff = @Backoff(
                    delay = 5000,
                    multiplier = 2.0
            )
    )
    public void sendEmail(String to,
                          String subject,
                          String text) {
        var message = new SimpleMailMessage();
        message.setFrom(String.format("%s <%s>", fromDisplayName, "takenCareAuto"));
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text + getSignature());
        mailSender.send(message);
    }

    @Recover
    public void logIfSendEmailFails(Exception ex,
                                    String to,
                                    String subject,
                                    String text) {
        log.error("Failed to send email to '{}' with subject '{}'. Error: {}", to, subject, ex.getMessage());
    }

    private String getSignature() {
        return String.format("""
                \n
                -------------------------------
                Best regards,
                -------------------------------
                This email was sent from the %s.
                If you have any queries, please contact us at %s
                """, fromDisplayName, helpMailAddress);
    }
}