package org.massine.auth.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.*;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.massine.auth.user.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Controller
@Validated
@RequiredArgsConstructor
public class AccountController {
    private final RegistrationService reg;
    private final PasswordResetService reset;

    @GetMapping("/register")
    public String registerForm() { return "register"; }

    @PostMapping("/register")
    public String register(@RequestParam @Email String email,
                           @RequestParam @Size(min=8, max=200) String password,
                           HttpServletRequest req,
                           Model model) {
        try {
            reg.startRegistration(email, password, baseUrl(req));
            model.addAttribute("message","Vérifiez votre e-mail pour confirmer votre compte.");
        } catch (IllegalArgumentException ex) {
            model.addAttribute("error", ex.getMessage());
        }
        return "register";
    }

    @GetMapping("/verify")
    public String verify(@RequestParam String token, Model model) {
        try {
            reg.verify(token);
            return "verify_success";
        } catch (IllegalArgumentException ex) {
            model.addAttribute("error", ex.getMessage());
            return "verify_success";
        }
    }

    @GetMapping("/forgot-password")
    public String forgotForm() { return "forgot_password"; }

    @PostMapping("/forgot-password")
    public String forgot(@RequestParam @Email String email,
                         HttpServletRequest req,
                         Model model) {
        reset.startReset(email, baseUrl(req));
        model.addAttribute("message","Si un compte existe, un e-mail a été envoyé.");
        return "forgot_password";
    }

    @GetMapping("/reset-password")
    public String resetForm(@RequestParam String token, Model model) {
        model.addAttribute("token", token);
        return "reset_password";
    }

    @PostMapping("/reset-password")
    public String doReset(@RequestParam String token,
                          @RequestParam @Size(min=8, max=200) String password,
                          Model model) {
        try {
            reset.completeReset(token, password);
            model.addAttribute("message","Mot de passe mis à jour. Vous pouvez vous connecter.");
        } catch (IllegalArgumentException ex) {
            model.addAttribute("error", ex.getMessage());
        }
        return "reset_password";
    }

    private String baseUrl(HttpServletRequest req) {
        String scheme = req.getHeader("X-Forwarded-Proto");
        String host   = req.getHeader("X-Forwarded-Host");
        if (scheme != null && host != null) return scheme + "://" + host;
        return req.getScheme() + "://" + req.getServerName() +
                ((req.getServerPort()==80||req.getServerPort()==443)?"":":"+req.getServerPort());
    }
}
