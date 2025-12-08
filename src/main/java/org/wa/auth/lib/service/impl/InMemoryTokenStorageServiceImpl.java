package org.wa.auth.lib.service.impl;

import org.springframework.stereotype.Component;
import org.wa.auth.lib.service.InMemoryTokenStorageService;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class InMemoryTokenStorageServiceImpl implements InMemoryTokenStorageService {

    private final Map<String, String> userTokens = new ConcurrentHashMap<>();

    public void saveToken(String email, String token) {
        userTokens.put(email, token);
    }

    public String getUserToken(String email) {
        return userTokens.get(email);
    }

    public Optional<String> getToken(String email) {
        return Optional.ofNullable(userTokens.get(email));
    }

    public void removeToken(final String email) {
        userTokens.remove(email);
    }

    public boolean hasToken(final String email) {
        return userTokens.containsKey(email);
    }
}
