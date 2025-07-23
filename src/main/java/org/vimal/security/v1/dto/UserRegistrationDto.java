package org.vimal.security.v1.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserRegistrationDto {
    private String username;
    private String password;
    private String email;
    private String firstName;
    private String middleName;
    private String lastName;
}