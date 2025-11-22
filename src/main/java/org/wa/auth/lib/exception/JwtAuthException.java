package org.wa.auth.lib.exception;

public class JwtAuthException extends IllegalStateException {
    public JwtAuthException(String message) {
        super(message);
    }
}
