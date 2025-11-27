package org.wa.auth.lib.service;

import org.wa.auth.lib.exception.UserAuthException;
import org.wa.auth.lib.model.jwt.JwtRequest;
import org.wa.auth.lib.model.jwt.JwtResponse;

public interface AuthService {
    JwtResponse login(JwtRequest authRequest) throws UserAuthException;
    JwtResponse getAccessToken(String refreshToken) throws UserAuthException;
    JwtResponse getRefreshToken(String refreshToken) throws UserAuthException;
}
