package org.massine.auth.user;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name="email_verification_token", schema="auth_schema")
public class EmailVerificationToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long id;
    public Long userId;
    @Column(unique = true, nullable = false)
    public String token;
    public Instant expiresAt;
    public boolean used = false;
    @Column(name = "login_url", nullable = true)
    public String loginUrl;
}