package org.vimal.security.v1.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
public class RoleCreationDto {
    private String roleName;
    private String description;
    private Set<String> permissions;
}