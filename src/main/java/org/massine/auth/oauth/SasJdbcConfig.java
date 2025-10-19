package org.massine.auth.oauth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;

import javax.sql.DataSource;

@Configuration
public class SasJdbcConfig {

    @Bean
    JdbcRegisteredClientRepository registeredClientRepository(DataSource ds) {
        return new JdbcRegisteredClientRepository(new JdbcTemplate(ds));
    }

    @Bean
    OAuth2AuthorizationService authorizationService(DataSource ds,
                                                    JdbcRegisteredClientRepository repo) {
        return new JdbcOAuth2AuthorizationService(new JdbcTemplate(ds), repo);
    }

    @Bean
    OAuth2AuthorizationConsentService consentService(DataSource ds,
                                                     JdbcRegisteredClientRepository repo) {
        return new JdbcOAuth2AuthorizationConsentService(new JdbcTemplate(ds), repo);
    }
}
