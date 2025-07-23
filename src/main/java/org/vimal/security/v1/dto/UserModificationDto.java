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
public class UserModificationDto {
    private boolean isModified;
    private boolean shouldRemoveTokens;
    private Set<String> invalidInputs;
}