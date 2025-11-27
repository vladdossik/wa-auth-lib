package org.wa.auth.lib.config;

import io.netty.channel.ChannelOption;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.ExchangeFilterFunctions;
import org.springframework.web.reactive.function.client.WebClient;
import org.wa.auth.lib.exception.UserAuthException;
import reactor.netty.http.client.HttpClient;
import java.time.Duration;


@Configuration
public class WebClientConfig {

    @Value("${integration.auth-service.base-url}")
    private String authServiceUrl;
    @Value("${integration.auth-service.timeout}")
    private int timeout;

    @Bean
    public WebClient authServiceWebClient() {
        HttpClient httpClient = HttpClient.create()
                .responseTimeout(Duration.ofMillis(timeout))
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, timeout);
        return WebClient.builder()
                .baseUrl(authServiceUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .filter(ExchangeFilterFunctions.statusError(
                        HttpStatusCode::isError, response ->
                                new UserAuthException("Error of connecting: " + response.statusCode())
                ))
                .build();
    }
}
