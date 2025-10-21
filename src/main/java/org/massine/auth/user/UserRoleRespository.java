package org.massine.auth.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRoleRespository  extends JpaRepository<UserRole, UserRoleId> {

}
