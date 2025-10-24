package org.massine.auth.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class RegisteredClientForm {

    @NotBlank
    @Size(max = 128)
    private String clientId;

    @NotBlank
    @Size(max = 128)
    private String clientName;

    @NotBlank
    private String type;

    @Size(max = 256)
    private String clientSecret;

    @Size(max = 2048)
    private String redirectUris;

    @Size(max = 2048)
    private String postLogoutRedirectUris;

    @Size(max = 1024)
    private String scopes;


    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getClientName() { return clientName; }
    public void setClientName(String clientName) { this.clientName = clientName; }

    public String getType() { return type; }
    public void setType(String type) { this.type = type; }

    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

    public String getRedirectUris() { return redirectUris; }
    public void setRedirectUris(String redirectUris) { this.redirectUris = redirectUris; }

    public String getPostLogoutRedirectUris() { return postLogoutRedirectUris; }
    public void setPostLogoutRedirectUris(String postLogoutRedirectUris) { this.postLogoutRedirectUris = postLogoutRedirectUris; }

    public String getScopes() { return scopes; }
    public void setScopes(String scopes) { this.scopes = scopes; }
}
