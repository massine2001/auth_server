package org.massine.auth.crypto;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwkService {

    private final JdbcTemplate jdbc;


    public RSAPrivateKey loadActivePrivateKey() {
        return jdbc.queryForObject(
                "SELECT private_pem FROM auth_schema.oauth2_jwk WHERE active=true LIMIT 1",
                (rs, i) -> {
                    try {
                        return (RSAPrivateKey) PemUtils.parseRSAPrivateKey(rs.getString("private_pem"));
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
        );
    }

    private RSAKey mapToPublicRSA(ResultSet rs) throws SQLException {
        try {
            String kid = rs.getString("kid");
            String pub = rs.getString("public_pem");
            RSAPublicKey pubKey = (RSAPublicKey) PemUtils.parseRSAPublicKey(pub);
            return new RSAKey.Builder(pubKey)
                    .keyID(kid)
                    .algorithm(JWSAlgorithm.RS256)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to map public RSA key", e);
        }
    }

    @Transactional
    public void generateAndActivateRSA() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(3072);
            KeyPair kp = kpg.generateKeyPair();

            String kid = UUID.randomUUID().toString();
            String pubPem = PemUtils.toPem("PUBLIC KEY", kp.getPublic().getEncoded());
            String prvPem = PemUtils.toPem("PRIVATE KEY", kp.getPrivate().getEncoded());

            jdbc.update("INSERT INTO oauth2_jwk(kid,kty,alg,public_pem,private_pem,active) VALUES (?,?,?,?,?,true)",
                    kid, "RSA", "RS256", pubPem, prvPem);

        } catch (Exception e) {
            throw new RuntimeException("Key rotation failed", e);
        }
    }
    public JWKSet loadActivePublicSet() {
        var rows = jdbc.query(
                "SELECT kid,kty,alg,public_pem FROM auth_schema.oauth2_jwk WHERE active=true",
                (rs, i) -> {
                    var kid = rs.getString("kid");
                    var pub = rs.getString("public_pem");
                    RSAPublicKey pubKey = null;
                    try {
                        pubKey = (RSAPublicKey) PemUtils.parseRSAPublicKey(pub);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                    return new RSAKey.Builder(pubKey).keyID(kid).algorithm(JWSAlgorithm.RS256).build();
                }
        );
        var jwks = new ArrayList<JWK>(rows);
        if (jwks.isEmpty()) throw new IllegalStateException("No active JWK");
        return new JWKSet(jwks);
    }

    @Transactional
    public void ensureActiveKeyExists() {
        Integer n = jdbc.queryForObject(
                "SELECT COUNT(*) FROM auth_schema.oauth2_jwk WHERE active=true", Integer.class
        );
        if (n == null || n == 0) {
            generateAndActivateRSA();
        }
    }

    public RSAKey loadActiveSignerKey() {
        var list = jdbc.query("""
            SELECT kid, public_pem, private_pem
            FROM auth_schema.oauth2_jwk WHERE active=true
            ORDER BY created_at DESC
            LIMIT 1
        """, (rs, i) -> {
            var kid = rs.getString("kid");
            RSAPublicKey pub = null;
            try {
                pub = (RSAPublicKey) PemUtils.parseRSAPublicKey(rs.getString("public_pem"));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            PrivateKey prv = null;
            try {
                prv = (PrivateKey) PemUtils.parseRSAPrivateKey(rs.getString("private_pem"));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return new RSAKey.Builder(pub).privateKey(prv).keyID(kid).algorithm(JWSAlgorithm.RS256).build();
        });
        if (list.isEmpty()) {
            throw new IllegalStateException("No active JWK");
        }
        return list.get(0);
    }

}
