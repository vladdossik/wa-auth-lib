package org.wa.auth.lib.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.wa.auth.lib.exception.UserAuthException;
import org.wa.auth.lib.model.jwt.JwtRequest;
import org.wa.auth.lib.model.jwt.JwtResponse;
import org.wa.auth.lib.model.jwt.RefreshJwtRequest;
import org.wa.auth.lib.service.AuthService;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final WebClient authServiceWebClient;
    @Value("${auth-service.login-endpoint}")
    private String loginUrl;
    @Value("${auth-service.accessToken-endpoint}")
    private String accessTokenUrl;
    @Value("${auth-service.refreshToken-endpoint}")
    private String refreshTokenUrl;

    @Override
    public JwtResponse login(JwtRequest authRequest) throws UserAuthException {
        log.debug("Attempting login for user: {}", authRequest.login());
        try {
            return authServiceWebClient.post()
                    .uri(loginUrl)
                    .bodyValue(authRequest)
                    .retrieve()
                    .onStatus(HttpStatus.UNAUTHORIZED::equals, response ->
                            Mono.error(new UserAuthException("Invalid credentials")))
                    .onStatus(HttpStatusCode::is4xxClientError, response ->
                            Mono.error(new UserAuthException("Authentication failed")))
                    .bodyToMono(JwtResponse.class)
                    .doOnSuccess(response ->
                            log.debug("Login successful for user: {}", authRequest.login()))
                    .doOnError(error ->
                            log.error("Login failed for user {}: {}", authRequest.login(), error.getMessage()))
                    .block();

        } catch (Exception e) {
            throw new UserAuthException("Login failed: ", e);
        }
    }

    @Override
    public JwtResponse getAccessToken(String refreshToken) throws UserAuthException {
        log.debug("Getting new access token using refresh token");
        return operateRefreshToken(refreshToken, accessTokenUrl, "access token");
    }

    @Override
    public JwtResponse getRefreshToken(String refreshToken) throws UserAuthException {
        log.debug("Refreshing tokens");
        return operateRefreshToken(refreshToken, refreshTokenUrl, "refresh token");
    }

    private JwtResponse operateRefreshToken(String refreshToken, String url, String operationName)
            throws UserAuthException {
        try {
            RefreshJwtRequest request = new RefreshJwtRequest();
            request.setRefreshToken(refreshToken);
            return authServiceWebClient.post()
                    .uri(url)
                    .bodyValue(request)
                    .retrieve()
                    .onStatus(HttpStatus.UNAUTHORIZED::equals, response ->
                            Mono.error(new UserAuthException("Invalid refresh token")))
                    .bodyToMono(JwtResponse.class)
                    .doOnSuccess(response -> log.debug("Successfully obtained new {}", operationName))
                    .doOnError(error -> log.error("Failed to get {}: {}", operationName, error.getMessage()))
                    .block();
        } catch (Exception e) {
            throw new UserAuthException(String.format("Failed to get %s", operationName), e);
        }
    }
}
