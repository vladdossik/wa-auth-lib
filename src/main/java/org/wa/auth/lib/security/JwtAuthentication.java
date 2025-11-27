package org.wa.auth.lib.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.wa.auth.lib.exception.JwtAuthException;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

public record JwtAuthentication(
        String email,
        String phone,
        Set<String> roles,
        boolean authenticated
) implements Authentication {
    public JwtAuthentication(String email, Set<String> roles) {
        this(email, null, roles, true);
    }

    public JwtAuthentication(String email, String phone, Set<String> roles) {
        this(email, phone, roles, true);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (roles == null) return Set.of();
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return email;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws JwtAuthException {
        throw new JwtAuthException("JwtAuthentication is immutable");
    }

    @Override
    public String getName() {
        return email;
    }
}
