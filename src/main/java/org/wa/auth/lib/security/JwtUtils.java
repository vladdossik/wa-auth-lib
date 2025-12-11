package org.wa.auth.lib.security;

import io.jsonwebtoken.Claims;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class JwtUtils {
    public static JwtAuthentication generate(Claims claims) {
        final JwtAuthentication jwtInfoToken = new JwtAuthentication();
        jwtInfoToken.setRoles(getRoles(claims));
        jwtInfoToken.setEmail(claims.getSubject());
        return jwtInfoToken;
    }

    private static Set<String> getRoles(Claims claims) {
        List<?> rolesFromToken = claims.get("roles", List.class);
        if (rolesFromToken == null) return Set.of();

        return rolesFromToken.stream()
                .map(JwtUtils::extractRoleName)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    private static String extractRoleName(Object role) {
        if (role instanceof java.util.Map<?, ?> map) {
            Object name = map.get("name");
            return name != null ? name.toString() : null;
        }
        return role.toString();
    }
}
