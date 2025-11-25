package org.wa.auth.lib.model.jwt;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RefreshJwtRequest {
    @NotBlank
    private String refreshToken;
}
