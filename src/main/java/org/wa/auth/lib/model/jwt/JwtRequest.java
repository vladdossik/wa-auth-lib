package org.wa.auth.lib.model.jwt;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record JwtRequest(
        @NotBlank(message = "Login cannot be blank")
        @Email(message = "Login should be valid")
        String login,
        @NotBlank(message = "Password cannot be blank")
        @Size(min = 6, message = "Password must be at least 6 characters")
        String password
) {}
