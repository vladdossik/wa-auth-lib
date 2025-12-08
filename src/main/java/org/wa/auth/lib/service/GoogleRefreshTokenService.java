package org.wa.auth.lib.service;

import io.netty.channel.ChannelOption;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.wa.auth.lib.exception.ParseTokenException;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import java.time.Duration;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class GoogleRefreshTokenService {
    @Value("${integration.google-fit.base-url}")
    private String googleFitBaseUrl;

    @Value("${integration.google-fit.timeout}")
    private int timeout;

    @Value("${GOOGLE_CLIENT_ID}")
    private String clientId;

    @Value("${GOOGLE_CLIENT_SECRET}")
    private String clientSecret;

    @Value("${google-fit.redirect-url}")
    private String redirectUrl;

    @Value("${google-fit.authorize-endpoint}")
    private String tokenEndpoint;

    private final InMemoryTokenStorageService tokenStorage;
    private WebClient webClient;

    @PostConstruct
    private void init() {
        HttpClient httpClient = HttpClient.create()
                .responseTimeout(Duration.ofMillis(timeout))
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, timeout);
        this.webClient = WebClient.builder()
                .baseUrl(googleFitBaseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }

    public Mono<Map<String, String>> exchangeCodeForTokens(String code, String email) {
        return webClient.post()
                .uri(tokenEndpoint)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("code", code)
                        .with("client_id", clientId)
                        .with("client_secret", clientSecret)
                        .with("redirect_uri", redirectUrl)
                        .with("grant_type", "authorization_code"))
                .retrieve()
                .onStatus(HttpStatusCode::isError, clientResponse ->
                        clientResponse.bodyToMono(String.class).flatMap(errorBody
                                -> Mono.error(new ParseTokenException("Не удалось прочитать токен")))
                )
                .bodyToMono(new ParameterizedTypeReference<Map<String, String>>() {
                })
                .map(tokens -> {
                    String refreshToken = tokens.get("refresh_token");
                    if (email != null && refreshToken != null) {
                        tokenStorage.saveToken(email, refreshToken);
                    }
                    return tokens;
                });
    }
}
