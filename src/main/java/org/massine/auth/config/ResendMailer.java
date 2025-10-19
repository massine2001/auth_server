package org.massine.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Component
public class ResendMailer implements Mailer {

    private final WebClient web;
    private final String from;

    public ResendMailer(
            @Value("${RESEND_API_KEY}") String apiKey,
            @Value("${RESEND_FROM}") String from) {

        this.from = from;
        this.web = WebClient.builder()
                .baseUrl("https://api.resend.com")
                .defaultHeader("Authorization", "Bearer " + apiKey)
                .build();
    }

    @Override
    public void send(String to, String subject, String html) {
        web.post()
                .uri("/emails")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("""
          {
            "from": "%s",
            "to": ["%s"],
            "subject": "%s",
            "html": %s
          }
          """.formatted(from, to, subject, toJsonString(html)))
                .retrieve()
                .bodyToMono(String.class)
                .onErrorResume(e -> {
                    System.err.println("Mail error: " + e.getMessage());
                    return Mono.empty();
                })
                .block();
    }

    private static String toJsonString(String s) {
        return "\"" + s.replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "") + "\"";
    }
}
