package org.vimal.security.v1.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.vimal.security.v1.model.PermissionModel;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ResolvedPermissionsDto {
    private Set<PermissionModel> permissions;
    private Set<String> missingPermissions;
}