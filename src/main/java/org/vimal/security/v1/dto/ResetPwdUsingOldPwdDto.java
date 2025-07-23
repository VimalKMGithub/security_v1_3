package org.vimal.security.v1.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResetPwdUsingOldPwdDto {
    private String oldPassword;
    private String newPassword;
    private String confirmPassword;
}