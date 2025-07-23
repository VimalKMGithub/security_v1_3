package org.vimal.security.v1.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResetPwdDto {
    private String username;
    private String email;
    private String usernameOrEmail;
    private String otp;
    private String password;
    private String confirmPassword;
}