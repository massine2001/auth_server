package org.massine.auth.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;

import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/clients")
@PreAuthorize("hasAuthority('admin')")
public class RegisteredClientController {

    private final RegisteredClientRepository repository;
    private final JdbcTemplate jdbcTemplate;
    private final PasswordEncoder passwordEncoder;

    public RegisteredClientController(RegisteredClientRepository repository,
                                      JdbcTemplate jdbcTemplate,
                                      PasswordEncoder passwordEncoder) {
        this.repository = repository;
        this.jdbcTemplate = jdbcTemplate;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping
    public String list(Model model) {
        List<String> ids = jdbcTemplate.queryForList("SELECT id FROM oauth2_registered_client", String.class);
        List<RegisteredClient> clients = ids.stream()
                .map(repository::findById)
                .filter(c -> c != null)
                .collect(Collectors.toList());
        model.addAttribute("clients", clients);
        return "clients/list";
    }

    @GetMapping("/new")
    public String newForm(Model model) {
        model.addAttribute("form", new RegisteredClientForm());
        model.addAttribute("isNew", true);
        return "clients/form";
    }

    @PostMapping
    public String create(@Valid @ModelAttribute("form") RegisteredClientForm form) {
        RegisteredClient client = buildClient(form, UUID.randomUUID().toString(), null);
        repository.save(client);
        return "redirect:/clients";
    }

    @GetMapping("/{id}/edit")
    public String editForm(@PathVariable String id, Model model) {
        RegisteredClient client = repository.findById(id);
        if (client == null) throw new IllegalArgumentException("Client not found");
        RegisteredClientForm form = toForm(client);
        model.addAttribute("form", form);
        model.addAttribute("id", id);
        model.addAttribute("isNew", false);
        return "clients/form";
    }

    @PostMapping("/{id}")
    public String update(@PathVariable String id, @Valid @ModelAttribute("form") RegisteredClientForm form) {
        RegisteredClient existing = repository.findById(id);
        if (existing == null) throw new IllegalArgumentException("Client not found");
        RegisteredClient updated = buildClient(form, existing.getId(), existing);
        int rows = jdbcTemplate.update(
                "UPDATE oauth2_registered_client SET client_id = ?, client_name = ? WHERE id = ?",
                form.getClientId().trim(),
                form.getClientName().trim(),
                id
        );

        repository.save(updated);
        return "redirect:/clients";
    }

    @PostMapping("/{id}/delete")
    public String delete(@PathVariable String id) {
        jdbcTemplate.update("DELETE FROM oauth2_registered_client WHERE id = ?", id);
        return "redirect:/clients";
    }

    private RegisteredClient buildClient(RegisteredClientForm form, String id, RegisteredClient existingOrNull) {
        RegisteredClient.Builder b = RegisteredClient.withId(id)
                .clientId(form.getClientId().trim())
                .clientName(form.getClientName().trim());

        if ("SPA".equalsIgnoreCase(form.getType())) {
            b.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .clientSettings(ClientSettings.builder()
                            .requireProofKey(true)
                            .requireAuthorizationConsent(true)
                            .build());

            if (StringUtils.hasText(form.getRedirectUris())) {
                b.redirectUris(uris -> uris.addAll(splitComma(form.getRedirectUris())));
            }
            if (StringUtils.hasText(form.getScopes())) {
                b.scopes(scopes -> scopes.addAll(splitSpace(form.getScopes())));
            }
        } else if ("M2M".equalsIgnoreCase(form.getType())) {
            b.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);

            if (StringUtils.hasText(form.getClientSecret())) {
                b.clientSecret(passwordEncoder.encode(form.getClientSecret()));
            } else if (existingOrNull != null && StringUtils.hasText(existingOrNull.getClientSecret())) {
                b.clientSecret(existingOrNull.getClientSecret());
            }

            if (StringUtils.hasText(form.getScopes())) {
                b.scopes(scopes -> scopes.addAll(splitSpace(form.getScopes())));
            }
        } else {
            throw new IllegalArgumentException("Unknown client type: " + form.getType());
        }

        return b.build();
    }

    private static List<String> splitComma(String s) {
        return List.of(s.split("\\s*,\\s*")).stream()
                .filter(StringUtils::hasText)
                .collect(Collectors.toList());
    }

    private static List<String> splitSpace(String s) {
        return List.of(s.split("\\s+")).stream()
                .filter(StringUtils::hasText)
                .collect(Collectors.toList());
    }

    private RegisteredClientForm toForm(RegisteredClient client) {
        RegisteredClientForm f = new RegisteredClientForm();
        f.setClientId(client.getClientId());
        f.setClientName(client.getClientName());
        f.setRedirectUris(String.join(", ", client.getRedirectUris()));
        f.setScopes(String.join(" ", client.getScopes()));
        if (client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            f.setType("SPA");
        } else if (client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.CLIENT_CREDENTIALS)) {
            f.setType("M2M");
        }
        return f;
    }
}
