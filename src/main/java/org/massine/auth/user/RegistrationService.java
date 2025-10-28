package org.massine.auth.user;

import lombok.RequiredArgsConstructor;
import org.massine.auth.config.Mailer;
import org.massine.auth.util.Tokens;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.Duration;

@Service
public class RegistrationService {
    private final UserRepository users;
    private final RoleRepository roles;
    private final EmailVerificationTokenRepo emailTokens;
    private final PasswordEncoder pe;
    private final Mailer mailer;
    private final UserRoleRespository userRole;

    public RegistrationService(UserRepository users, RoleRepository roles, EmailVerificationTokenRepo emailTokens, PasswordEncoder pe, Mailer mailer, UserRoleRespository userRole) {
        this.users = users;
        this.roles = roles;
        this.emailTokens = emailTokens;
        this.pe = pe;
        this.mailer = mailer;
        this.userRole = userRole;
    }

    @Transactional
    public void startRegistration(String email, String rawPassword, String baseUrl, String loginUrl) {
        String username = email.toLowerCase();
        users.findByEmail(email).ifPresent(u -> { throw new IllegalArgumentException("Email déjà utilisé"); });

        UserEntity u = new UserEntity();
        u.setUsername(username);
        u.setEmail(email);
        u.setPasswordHash(pe.encode(rawPassword));
        u.setEnabled(false);
        users.save(u);

        UserRole ur = new UserRole();
        ur.userId = u.getId();
        ur.roleId = 2L;
        userRole.save(ur);

        String tok = Tokens.randomUrlToken(32);
        EmailVerificationToken evt = new EmailVerificationToken();
        evt.userId = u.getId();
        evt.token = tok;
        evt.expiresAt = Instant.now().plus(Duration.ofHours(24));
        emailTokens.save(evt);

        String link = baseUrl + "/verify?token=" + tok;
        if (loginUrl != null && !loginUrl.isBlank()) {
            String enc = URLEncoder.encode(loginUrl, StandardCharsets.UTF_8);
            link = link + "&login=" + enc;
        }
        String html = """
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="color-scheme" content="light dark">
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #f6f8fa;
      color: #24292e;
      margin: 0;
      padding: 2rem;
    }
    .container {
      max-width: 480px;
      margin: 0 auto;
      background: #ffffff;
      border-radius: 8px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
      padding: 2rem;
    }
    h1 { font-size: 1.2rem; margin-top: 0; text-align: center; }
    p { line-height: 1.5; }
    a.button {
      display: inline-block;
      background: #007bff;
      color: #ffffff !important;
      text-decoration: none;
      padding: 0.75rem 1.25rem;
      border-radius: 6px;
      margin: 1rem 0;
    }
    .footer {
      font-size: 0.8rem;
      color: #6c757d;
      text-align: center;
      margin-top: 2rem;
    }
    code {
      background: #f1f1f1;
      padding: 2px 4px;
      border-radius: 4px;
      font-size: 0.9em;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Confirmez votre adresse e-mail</h1>
    <p>Bonjour,</p>
    <p>Merci de créer un compte sur <strong>auth.massine.org</strong>.</p>
    <p>Pour activer votre compte, veuillez confirmer votre adresse e-mail en cliquant sur le bouton ci-dessous :</p>
    <p style="text-align:center;">
      <a href="%s" class="button" target="_blank">Confirmer mon e-mail</a>
    </p>
    <p>Ce lien expire dans <strong>24 heures</strong>.</p>
    <hr style="border:none;border-top:1px solid #eee;margin:1.5rem 0;">
    <p>Si le bouton ne fonctionne pas, copiez et collez ce lien dans votre navigateur :</p>
    <p><code>%s</code></p>
    <div class="footer">
      Cet e-mail a été envoyé automatiquement. Merci de ne pas y répondre.
    </div>
  </div>
</body>
</html>
""".formatted(link, link);

        mailer.send(email, "Vérification de votre e-mail", html);
    }

    @Transactional
    public void verify(String token) {
        var evt = emailTokens.findByTokenAndUsedFalseAndExpiresAtAfter(token, Instant.now())
                .orElseThrow(() -> new IllegalArgumentException("Lien invalide ou expiré"));
        var u = users.findById(evt.userId).orElseThrow();
        u.setEnabled(true);
        users.save(u);
        evt.used = true;
        emailTokens.save(evt);
    }
}
