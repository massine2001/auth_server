package org.massine.auth.user;

import jakarta.persistence.*;

@Entity @Table(name="roles", schema="auth_schema")
public class RoleEntity {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) Long id;
    @Column(nullable=false, unique=true) String name;
}
