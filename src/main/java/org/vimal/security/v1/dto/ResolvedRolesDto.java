package org.vimal.security.v1.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.vimal.security.v1.model.RoleModel;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ResolvedRolesDto {
    private Set<RoleModel> roles;
    private Set<String> missingRoles;
}