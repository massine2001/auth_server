package org.massine.auth.crypto;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Profile("app")
@Component
@RequiredArgsConstructor
class KeyBootstrap implements ApplicationRunner {
    private final JwkService jwkService;

    @Override public void run(ApplicationArguments args) {
        try {
            jwkService.loadActivePublicSet();
        } catch (IllegalStateException e) {
            jwkService.generateAndActivateRSA();
        }
    }
}
