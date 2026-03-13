package org.wa.auth.lib.security;

import io.jsonwebtoken.Claims;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class JwtUtils {
    public static JwtAuthentication createJwtAuth(Claims claims) {
        final JwtAuthentication jwtInfoToken = new JwtAuthentication();
        jwtInfoToken.setRoles(getRoles(claims));
        jwtInfoToken.setUserId(UUID.fromString(claims.getSubject()));
        jwtInfoToken.setEmail(getEmail(claims));
        jwtInfoToken.setGoogleToken(getGoogleToken(claims));
        return jwtInfoToken;
    }

    private static String getGoogleToken(Claims claims) {
        return claims.get("google_refresh_token", String.class);
    }

    private static String getEmail(Claims claims) {
        return claims.get("email", String.class);
    }

    private static Set<String> getRoles(Claims claims) {
        List<?> rolesFromToken = claims.get("roles", List.class);
        if (rolesFromToken == null) return Set.of();

        return rolesFromToken.stream()
                .map(role -> {
                    if (role instanceof java.util.Map<?, ?> map) {
                        return map.get("name").toString();
                    }
                    return role.toString();
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }
}

