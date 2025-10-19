package org.massine.auth.user;

import jakarta.persistence.*;
import org.springframework.data.jpa.repository.*;
import org.springframework.stereotype.Repository;
import java.time.Instant;
import java.util.*;

@Entity
@Table(name="email_verification_token", schema="auth_schema")
class EmailVerificationToken {
    @Id
    @GeneratedValue(strategy=GenerationType.IDENTITY) Long id;
    Long userId;
    @Column(unique=true, nullable=false) String token;
    Instant expiresAt;
    boolean used = false;
}

@Entity
@Table(name="password_reset_token", schema="auth_schema")
class PasswordResetToken {
    @Id @GeneratedValue(strategy=GenerationType.IDENTITY) Long id;
    Long userId;
    @Column(unique=true, nullable=false) String token;
    Instant expiresAt;
    boolean used = false;
}

@Repository
interface EmailVerificationTokenRepo extends JpaRepository<EmailVerificationToken, Long> {
    Optional<EmailVerificationToken> findByTokenAndUsedFalseAndExpiresAtAfter(String token, Instant now);
}

@Repository
interface PasswordResetTokenRepo extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByTokenAndUsedFalseAndExpiresAtAfter(String token, Instant now);
}
