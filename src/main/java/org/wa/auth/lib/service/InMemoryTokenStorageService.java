package org.wa.auth.lib.service;

import java.util.Optional;

public interface InMemoryTokenStorageService {

    void saveToken(String email, String token);

    String getUserToken(String email);

    Optional<String> getToken(String email);

    void removeToken(String email);

    boolean hasToken(String email);
}
