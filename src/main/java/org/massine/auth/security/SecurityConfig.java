package org.massine.auth.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  CorsConfigurationSource corsConfigurationSource(
      @Value("${APP_CORS_ALLOWED_ORIGINS:}") String allowedOriginsEnv
  ) {
    var cfg = new CorsConfiguration();

    List<String> origins = Arrays.stream(allowedOriginsEnv.split(","))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .toList();
    if (!origins.isEmpty()) {
      cfg.setAllowedOrigins(origins);
    }

    cfg.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
    cfg.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    cfg.setAllowCredentials(false);
    cfg.setMaxAge(Duration.ofHours(1));

    var source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", cfg);
    return source;
  }

  @Bean
  @Order(1)
  SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
    var as = OAuth2AuthorizationServerConfigurer.authorizationServer();

    http
      .securityMatcher(as.getEndpointsMatcher())
      .with(as, authz -> authz.oidc(Customizer.withDefaults()))
      .csrf(csrf -> csrf.ignoringRequestMatchers(as.getEndpointsMatcher()))
      .cors(Customizer.withDefaults()) // ← utilise le bean corsConfigurationSource
      .exceptionHandling(e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
      .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
      .authorizeHttpRequests(a -> a
        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
        .requestMatchers("/.well-known/**", "/oauth2/jwks").permitAll()
        .anyRequest().authenticated())
      .headers(h -> h
        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).preload(true))
        .referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
      );

    return http.build();
  }

  @Bean
  @Order(2)
  SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
    http
      .authorizeHttpRequests(a -> a
        .requestMatchers("/", "/register", "/verify", "/forgot-password", "/reset-password").permitAll()
        .requestMatchers(HttpMethod.POST, "/register", "/forgot-password", "/reset-password").permitAll()
        .requestMatchers("/clients/**").access((authentication, context) -> {
          var auth = authentication.get();
          if (auth == null || !auth.isAuthenticated()) return new AuthorizationDecision(false);
          return new AuthorizationDecision(
            auth.getAuthorities().stream()
              .map(GrantedAuthority::getAuthority)
              .filter(Objects::nonNull)
              .map(String::toUpperCase)
              .anyMatch(s -> s.contains("ADMIN"))
          );
        })
        .anyRequest().authenticated())
      .formLogin(f -> f
        .loginPage("/login")
        .successHandler(new SavedRequestAwareAuthenticationSuccessHandler())
        .permitAll())
      .logout(l -> l.logoutUrl("/logout").logoutSuccessUrl("/?logout=1").permitAll())
      .cors(Customizer.withDefaults());

    return http.build();
  }

  @Bean
  PasswordEncoder passwordEncoder() {
    return org.springframework.security.crypto.factory.PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  @Bean
  AuthorizationServerSettings authzSettings(@Value("${APP_ISSUER}") String issuer) {
    return AuthorizationServerSettings.builder().issuer(issuer).build();
  }
}
