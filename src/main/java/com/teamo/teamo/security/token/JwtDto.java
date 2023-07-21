package com.teamo.teamo.security.token;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class JwtDto {
    private String grantType;
    private String accessToken;
    private String refreshToken;
    private Long accessTokenExpiresIn;

    @Builder
    public JwtDto(String grantType, String accessToken, String refreshToken, Long accessTokenExpiresIn) {
        this.grantType = grantType;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.accessTokenExpiresIn = accessTokenExpiresIn;
    }
}
