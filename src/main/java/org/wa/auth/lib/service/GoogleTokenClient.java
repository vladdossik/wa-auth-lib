package org.wa.auth.lib.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.wa.auth.lib.exception.TokenNotFoundException;
import org.wa.auth.lib.util.AuthContextHolder;
import java.util.Map;

@Service
@Slf4j
@RequiredArgsConstructor
public class GoogleTokenClient {
    private final WebClient googleTokenWebClient;
    @Value("${auth-service.googleRefreshToken-endpoint}")
    private String tokenUrl;

    public String getGoogleToken() {
        try {
            String email = AuthContextHolder.getEmail();
            Map<String, Object> response = googleTokenWebClient.get()
                    .uri(tokenUrl)
                    .retrieve()
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                    .doOnSuccess(r ->
                            log.debug("Successfully fetched Google token for user: {}", email))
                    .doOnError(error ->
                            log.error("Failed to fetch Google token for user: {}", email, error))
                    .block();

            return extractGoogleTokenFromResponse(response, email);

        } catch (Exception e) {
            log.error("Error getting Google token", e);
            throw new TokenNotFoundException("Failed to get Google token: " + e.getMessage());
        }
    }

    private String extractGoogleTokenFromResponse(Map<String, Object> response, String expectedEmail) {
        if (response == null) {
            throw new TokenNotFoundException("Empty response from auth-service");
        }

        String responseEmail = (String) response.get("email");
        if (responseEmail == null || !responseEmail.equals(expectedEmail)) {
            throw new TokenNotFoundException("Email mismatch in response. Expected: " +
                    expectedEmail + ", got: " + responseEmail);
        }

        String googleToken = (String) response.get("google_refresh_token");
        if (googleToken == null || googleToken.isBlank()) {
            throw new TokenNotFoundException("Google token not found in response");
        }

        log.info("Successfully retrieved Google token for user: {}", expectedEmail);
        return googleToken;
    }
}
