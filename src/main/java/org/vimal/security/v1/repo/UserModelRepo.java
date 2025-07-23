package org.vimal.security.v1.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.vimal.security.v1.model.RoleModel;
import org.vimal.security.v1.model.UserModel;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserModelRepo extends JpaRepository<UserModel, UUID> {
    Optional<UserModel> findByUsername(String username);

    boolean existsByUsername(String username);

    boolean existsByRealEmail(String realEmail);

    boolean existsByEmail(String email);

    Optional<UserModel> findByEmail(String storedEmail);

    List<UserModel> findByUsernameIn(Collection<String> usernames);

    List<UserModel> findByEmailIn(Collection<String> emails);

    long countByRoles_RoleName(String roleName);

    List<UserModel> findByRoles(RoleModel role);

    List<UserModel> findByRolesIn(Collection<RoleModel> roles);
}