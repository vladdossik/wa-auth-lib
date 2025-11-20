package org.wa.auth.lib.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.wa.auth.lib.exception.UserAuthException;
import org.wa.auth.lib.model.jwt.JwtRequest;
import org.wa.auth.lib.model.jwt.JwtResponse;
import org.wa.auth.lib.model.jwt.RefreshJwtRequest;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final WebClient authServiceWebClient;

    @Override
    public JwtResponse login(JwtRequest authRequest) throws UserAuthException {
        log.debug("Attempting login for user: {}", authRequest.getLogin());
        try {
            return authServiceWebClient.post()
                    .uri("/v1/auth/login")
                    .bodyValue(authRequest)
                    .retrieve()
                    .onStatus(HttpStatus.UNAUTHORIZED::equals, response ->
                            Mono.error(new UserAuthException("Invalid credentials")))
                    .onStatus(HttpStatusCode::is4xxClientError, response ->
                            Mono.error(new UserAuthException("Authentication failed")))
                    .bodyToMono(JwtResponse.class)
                    .doOnSuccess(response ->
                            log.debug("Login successful for user: {}", authRequest.getLogin()))
                    .doOnError(error ->
                            log.error("Login failed for user {}: {}", authRequest.getLogin(), error.getMessage()))
                    .block();

        } catch (Exception e) {
            throw new UserAuthException("Login failed: " + e.getMessage());
        }
    }

    @Override
    public JwtResponse getAccessToken(String refreshToken) throws UserAuthException {
        log.debug("Getting new access token using refresh token");
        try {
            RefreshJwtRequest request = new RefreshJwtRequest();
            request.setRefreshToken(refreshToken);

            return authServiceWebClient.post()
                    .uri("/v1/auth/token")
                    .bodyValue(request)
                    .retrieve()
                    .onStatus(HttpStatus.UNAUTHORIZED::equals, response ->
                            Mono.error(new UserAuthException("Invalid refresh token")))
                    .bodyToMono(JwtResponse.class)
                    .doOnSuccess(response -> log.debug("Successfully obtained new access token"))
                    .doOnError(error -> log.error("Failed to get access token: {}", error.getMessage()))
                    .block();
        } catch (Exception e) {
            throw new UserAuthException("Failed to get access token: " + e.getMessage());
        }
    }

    @Override
    public JwtResponse refresh(String refreshToken) throws UserAuthException {
        log.debug("Refreshing tokens");
        try {
            RefreshJwtRequest request = new RefreshJwtRequest();
            request.setRefreshToken(refreshToken);
            return authServiceWebClient.post()
                    .uri("/v1/auth/refresh")
                    .bodyValue(request)
                    .retrieve()
                    .onStatus(HttpStatus.UNAUTHORIZED::equals, response ->
                            Mono.error(new UserAuthException("Invalid refresh token")))
                    .bodyToMono(JwtResponse.class)
                    .doOnSuccess(response -> log.debug("Tokens refreshed successfully"))
                    .doOnError(error -> log.error("Token refresh failed: {}", error.getMessage()))
                    .block();
        } catch (Exception e) {
            throw new UserAuthException("Token refresh failed: " + e.getMessage());
        }
    }
}
