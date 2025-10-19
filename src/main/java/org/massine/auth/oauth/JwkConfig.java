package org.massine.auth.oauth;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.massine.auth.crypto.JwkService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
class JwkConfig {

    private final JwkService jwkService;

    @Bean
    InitializingBean jwkInit() {
        return jwkService::ensureActiveKeyExists;
    }

    @Bean
    JWKSource<SecurityContext> jwkSource() {
        RSAKey signer = jwkService.loadActiveSignerKey();
        return (selector, ctx) -> selector.select(new JWKSet(signer));
    }
}
