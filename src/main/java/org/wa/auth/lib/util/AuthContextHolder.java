package org.wa.auth.lib.util;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.wa.auth.lib.exception.JwtAuthException;
import org.wa.auth.lib.security.JwtAuthentication;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class AuthContextHolder {
    public static Collection<? extends GrantedAuthority> getCurrentUserAuthorities() {
        log.info("Getting authorities");
        return getCurrentAuthentication()
                .map(JwtAuthentication::getAuthorities)
                .orElse(Set.of());
    }

    public static String getRequiredUserEmail() {
        log.info("Getting email");
        return getCurrentUserEmail()
                .orElseThrow(() -> new JwtAuthException("User email is not available"));
    }

    public static boolean isAuthenticated() {
        return getCurrentAuthentication()
                .map(JwtAuthentication::isAuthenticated)
                .orElse(false);
    }

    public static JwtAuthentication getRequiredAuthentication() {
        return getCurrentAuthentication()
                .orElseThrow(() -> new JwtAuthException("User is not authenticated"));
    }

    private static Optional<JwtAuthentication> getCurrentAuthentication() {
        try {
            log.info("Getting current authentication from context");
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication instanceof JwtAuthentication jwtAuth &&
                    jwtAuth.isAuthenticated()) {
                return Optional.of(jwtAuth);
            }

            return Optional.empty();
        } catch (Exception e) {
            log.debug("Failed to get current authentication: {}", e.getMessage());

            return Optional.empty();
        }
    }

    private static Optional<String> getCurrentUserEmail() {
        return getCurrentAuthentication()
                .map(JwtAuthentication::getName)
                .filter(email -> !email.isBlank());
    }
}
