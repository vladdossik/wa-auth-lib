package org.wa.auth.lib.exception;
import jakarta.security.auth.message.AuthException;

public class UserAuthException extends AuthException {
    public UserAuthException(String message) {
        super(message);
    }
}
