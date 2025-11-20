package org.wa.auth.lib.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.Set;

@Slf4j
@Component
public class JwtService {
    private final SecretKey jwtAccessSecret;
    private final SecretKey jwtRefreshSecret;
    private final long expirationTime;
    private final long refreshInterval;

    public JwtService(
            @Value("${jwt.secret.access}") String jwtAccessSecret,
            @Value("${jwt.secret.refresh}") String jwtRefreshSecret,
            @Value("${jwt.expiration-ms}") long expirationTime,
            @Value("${jwt.refresh-expiration-ms}") long refreshInterval
    ) {
        this.jwtAccessSecret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtAccessSecret));
        this.jwtRefreshSecret = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtRefreshSecret));
        this.expirationTime = expirationTime;
        this.refreshInterval = refreshInterval;
    }

    public String generateAccessToken(@NonNull String email, @NonNull Set<String> roles) {
        Instant now = Instant.now();
        Date expirationDate = Date.from(now.plusMillis(expirationTime));
        return Jwts.builder()
                .subject(email)
                .issuedAt(Date.from(now))
                .expiration(expirationDate)
                .signWith(jwtAccessSecret)
                .claim("roles", roles)
                .compact();
    }

    public String generateRefreshToken(@NonNull String email, @NonNull Set<String> roles) {
        Instant now = Instant.now();
        Date expirationDate = Date.from(now.plusMillis(refreshInterval));
        return Jwts.builder()
                .subject(email)
                .issuedAt(Date.from(now))
                .expiration(expirationDate)
                .signWith(jwtRefreshSecret)
                .claim("roles", roles)
                .compact();
    }

    public boolean validateAccessToken(@NonNull String accessToken) {
        return validateToken(accessToken, jwtAccessSecret);
    }

    public boolean validateRefreshToken(@NonNull String refreshToken) {
        return validateToken(refreshToken, jwtRefreshSecret);
    }

    private boolean validateToken(@NonNull String token, @NonNull SecretKey secret) {
        try {
            Jwts.parser()
                    .verifyWith(secret)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token");
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token");
        } catch (MalformedJwtException e) {
            log.error("Malformed JWT token");
        } catch (SignatureException e) {
            log.error("Invalid JWT token");
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return false;
    }

    public Claims getAccessClaims(@NonNull String token) {
        return getClaims(token, jwtAccessSecret);
    }

    public Claims getClaims(@NonNull String token, @NonNull SecretKey secret) {
        return Jwts.parser()
                .verifyWith(secret)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
