package org.vimal.security.v1.dto;

import lombok.Getter;
import lombok.Setter;
import org.vimal.security.v1.model.UserModel;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
public class UserSummaryDto {
    private UUID id;
    private String firstName;
    private String middleName;
    private String lastName;
    private String username;
    private String email;
    private boolean emailVerified;
    private boolean mfaEnabled;
    private Set<UserModel.MfaType> mfaMethods;
    private boolean accountLocked;
    private boolean accountEnabled;
    private int failedLoginAttempts;
    private int failedMfaAttempts;
    private Set<String> roles;
    private Instant lastLoginAt;
    private Instant passwordChangedAt;
    private Instant createdAt;
    private Instant updatedAt;
    private Instant lastLockedAt;
    private String createdBy;
    private String updatedBy;
}