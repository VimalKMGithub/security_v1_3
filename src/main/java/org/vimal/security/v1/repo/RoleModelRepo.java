package org.vimal.security.v1.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.vimal.security.v1.model.RoleModel;

@Repository
public interface RoleModelRepo extends JpaRepository<RoleModel, String> {
}