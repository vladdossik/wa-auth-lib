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
    public static Collection<? extends GrantedAuthority> getRoles() {
        log.debug("Getting authorities");
        return getAuthenticationFromContext()
                .map(JwtAuthentication::getAuthorities)
                .orElse(Set.of());
    }

    public static String getEmail() {
        log.debug("Getting email");
        return getUserEmail()
                .orElseThrow(() -> new JwtAuthException("User email is not available"));
    }

    public static String getPhone() {
        log.debug("Getting phone");
        return getUserPhone()
                .orElseThrow(() -> new JwtAuthException("User phone is not available"));
    }

    public static boolean isAuthenticated() {
        return getAuthenticationFromContext()
                .map(JwtAuthentication::isAuthenticated)
                .orElse(false);
    }

    public static JwtAuthentication getAuthentication() {
        return getAuthenticationFromContext()
                .orElseThrow(() -> new JwtAuthException("User is not authenticated"));
    }

    public static void cleanUp() {
        SecurityContextHolder.clearContext();
        log.debug("Security context cleared");
    }

    private static Optional<JwtAuthentication> getAuthenticationFromContext() {
        try {
            log.info("Getting current authentication from context");
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication instanceof JwtAuthentication jwtAuth) {
                return Optional.of(jwtAuth);
            }

            return Optional.empty();
        } catch (Exception e) {
            log.debug("Failed to get current authentication: {}", e.getMessage());

            return Optional.empty();
        }
    }

    private static Optional<String> getUserEmail() {
        return getAuthenticationFromContext()
                .map(JwtAuthentication::getName)
                .filter(email -> email != null && !email.isBlank());
    }

    private static Optional<String> getUserPhone() {
        return getAuthenticationFromContext()
                .map(JwtAuthentication::getPhone)
                .filter(phone -> phone != null && !phone.isBlank());
    }
}
