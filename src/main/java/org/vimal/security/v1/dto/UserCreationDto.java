package org.vimal.security.v1.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
public class UserCreationDto {
    private String username;
    private String password;
    private String email;
    private String firstName;
    private String middleName;
    private String lastName;
    private Set<String> roles;
    private boolean emailVerified;
    private boolean accountLocked;
    private boolean accountEnabled;
}