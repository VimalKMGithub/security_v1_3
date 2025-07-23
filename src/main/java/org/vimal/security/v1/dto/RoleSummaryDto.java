package org.vimal.security.v1.dto;

import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.Set;

@Getter
@Setter
public class RoleSummaryDto {
    private String roleName;
    private String description;
    private boolean systemRole;
    private Set<String> permissions;
    private Instant createdAt;
    private Instant updatedAt;
    private String createdBy;
    private String updatedBy;
}