package org.massine.auth.user;

import jakarta.persistence.*;

@Entity
@Table(name="users", schema="auth_schema")
public class UserEntity {
    @Id
    @GeneratedValue(strategy=GenerationType.IDENTITY) Long id;
    @Column(nullable=false, unique=true) String username;
    @Column(unique=true) String email;
    @Column(name="password_hash", nullable=false) String passwordHash;
    boolean enabled=true;
}




