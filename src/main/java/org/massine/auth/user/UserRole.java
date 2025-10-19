package org.massine.auth.user;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import org.massine.auth.user.UserRoleId;

@Entity
@Table(name="user_roles", schema="auth_schema")
@IdClass(UserRoleId.class)
public class UserRole {
    @Id
    Long userId;
    @Id Long roleId;
}