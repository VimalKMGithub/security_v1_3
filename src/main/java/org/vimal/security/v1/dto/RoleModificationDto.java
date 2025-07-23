package org.vimal.security.v1.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RoleModificationDto {
    private boolean isModified;
    private boolean shouldRemoveTokensOfUsersHavingThisRole;
    private Set<String> invalidInputs;
}