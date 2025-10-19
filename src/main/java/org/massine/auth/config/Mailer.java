package org.massine.auth.config;

public interface Mailer {
    void send(String to, String subject, String html);
}
