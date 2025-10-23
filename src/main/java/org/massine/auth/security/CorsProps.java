package org.massine.auth.security;

import java.time.Duration;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.cors")
public class CorsProps {
    private List<String> allowedOrigins = List.of();
    private List<String> allowedMethods = List.of("GET","POST","OPTIONS");
    private List<String> allowedHeaders = List.of("Authorization","Content-Type");
    private boolean allowCredentials = false;
    private Duration maxAge = Duration.ofHours(1);

    public List<String> getAllowedOrigins() { return allowedOrigins; }
    public void setAllowedOrigins(List<String> allowedOrigins) { this.allowedOrigins = allowedOrigins; }
    public List<String> getAllowedMethods() { return allowedMethods; }
    public void setAllowedMethods(List<String> allowedMethods) { this.allowedMethods = allowedMethods; }
    public List<String> getAllowedHeaders() { return allowedHeaders; }
    public void setAllowedHeaders(List<String> allowedHeaders) { this.allowedHeaders = allowedHeaders; }
    public boolean isAllowCredentials() { return allowCredentials; }
    public void setAllowCredentials(boolean allowCredentials) { this.allowCredentials = allowCredentials; }
    public Duration getMaxAge() { return maxAge; }
    public void setMaxAge(Duration maxAge) { this.maxAge = maxAge; }
}
