package com.core.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtConfig {
    private String secret;
    private Long accessTokenExpiration;
    private Long refreshTokenExpiration;
    private String issuer;
    
    // Getter with default values
    public Long getAccessTokenExpiration() {
        return accessTokenExpiration != null ? accessTokenExpiration : 900000L; // 15 minutes
    }
    
    public Long getRefreshTokenExpiration() {
        return refreshTokenExpiration != null ? refreshTokenExpiration : 604800000L; // 7 days
    }
}