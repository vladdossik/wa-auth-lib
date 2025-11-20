package org.wa.auth.lib.model.jwt;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RefreshJwtRequest {
    private String refreshToken;
}
