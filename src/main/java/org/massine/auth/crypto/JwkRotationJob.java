package org.massine.auth.crypto;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

@Component
public class JwkRotationJob {

    private final JdbcTemplate jdbc;

    private static final Duration TOKEN_MAX_LIFETIME = Duration.ofDays(30);

    public JwkRotationJob(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Scheduled(cron = "0 0 3 * * *")
    @Transactional
    public void deactivateExpiredKeys() {
        try {
            var latestKid = jdbc.queryForObject(
                    "SELECT kid FROM oauth2_jwk WHERE active = true ORDER BY created_at DESC LIMIT 1",
                    String.class
            );

            if (latestKid == null) return;

            Instant cutoff = Instant.now().minus(TOKEN_MAX_LIFETIME);

            int updated = jdbc.update("""
                    UPDATE oauth2_jwk
                    SET active = false
                    WHERE active = true
                      AND kid <> ?
                      AND created_at < ?
                    """, latestKid, cutoff);

            if (updated > 0) {
                System.out.printf("[%s] JWK rotation: %d ancienne(s) clé(s) désactivée(s).%n", Instant.now(), updated);
            }

        } catch (Exception e) {
            System.err.printf("[%s] JWK rotation failed: %s%n", Instant.now(), e.getMessage());
        }
    }
}
