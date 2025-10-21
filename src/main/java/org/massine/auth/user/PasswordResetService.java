package org.massine.auth.user;

import lombok.RequiredArgsConstructor;
import org.massine.auth.config.Mailer;
import org.massine.auth.util.Tokens;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.*;

@Service
public class PasswordResetService {
    private final UserRepository users;
    private final PasswordResetTokenRepo resetTokens;
    private final PasswordEncoder pe;
    private final Mailer mailer;

    public PasswordResetService(UserRepository users, PasswordResetTokenRepo resetTokens, PasswordEncoder pe, Mailer mailer) {
        this.users = users;
        this.resetTokens = resetTokens;
        this.pe = pe;
        this.mailer = mailer;
    }

    @Transactional
    public void startReset(String email, String baseUrl) {
        var u = users.findByEmail(email).orElse(null);
        if (u == null) return;
        String tok = Tokens.randomUrlToken(32);
        var prt = new PasswordResetToken();
        prt.userId = u.getId();
        prt.token = tok;
        prt.expiresAt = Instant.now().plus(Duration.ofHours(1));
        resetTokens.save(prt);

        String link = baseUrl + "/reset-password?token=" + tok;

        String html = """
  <div style="font-family:system-ui,-apple-system,sans-serif;max-width:500px;margin:auto;padding:20px;
               background:#f9fafb;border-radius:8px;border:1px solid #e5e7eb;">
    <h2 style="color:#111827;">Réinitialisation de votre mot de passe</h2>
    <p style="color:#374151;line-height:1.5;">
      Vous avez demandé à réinitialiser votre mot de passe sur <strong>auth.massine.org</strong>.
    </p>
    <p style="text-align:center;margin:2rem 0;">
      <a href="%s" style="display:inline-block;background:#2563eb;color:white;
          padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:500;">
        Réinitialiser le mot de passe
      </a>
    </p>
    <p style="color:#6b7280;line-height:1.4;">
      Ce lien est valable pendant <strong>1 heure</strong>.<br>
      Si vous n'êtes pas à l'origine de cette demande, vous pouvez ignorer cet e-mail.
    </p>
    <hr style="border:none;border-top:1px solid #e5e7eb;margin:2rem 0;">
    <p style="font-size:0.85rem;color:#9ca3af;text-align:center;">
      &copy; 2025 auth.massine.org — Service d’authentification personnel d’Agharmiou Massine
    </p>
  </div>
  """.formatted(link);

        mailer.send(email, "Réinitialisation de votre mot de passe", html);
    }

    @Transactional
    public void completeReset(String token, String newPassword) {
        var prt = resetTokens.findByTokenAndUsedFalseAndExpiresAtAfter(token, Instant.now())
                .orElseThrow(() -> new IllegalArgumentException("Lien invalide ou expiré"));
        var u = users.findById(prt.userId).orElseThrow();
        u.setPasswordHash(pe.encode(newPassword));
        users.save(u);
        users.flush();
        prt.used = true;
        resetTokens.save(prt);
    }
}

