package org.vimal.security.v1.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserSelfUpdationDto {
    private String firstName;
    private String middleName;
    private String lastName;
    private String oldPassword;
    private String username;
    private String newPassword;
    private String confirmNewPassword;
}