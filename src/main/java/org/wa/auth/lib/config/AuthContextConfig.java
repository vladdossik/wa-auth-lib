package org.wa.auth.lib.config;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.wa.auth.lib.service.InMemoryTokenStorageService;
import org.wa.auth.lib.util.AuthContextHolder;

@Slf4j
@Configuration
@RequiredArgsConstructor
@ComponentScan(basePackages = "org.wa")
public class AuthContextConfig {
    private final InMemoryTokenStorageService storageService;

    @PostConstruct
    public void init() {
        AuthContextHolder.setStorageService(storageService);
        log.debug("AuthContextHolder initialized with InMemoryTokenStorageService");
    }
}
