package com.core.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.List;

@Data
@Configuration
@ConfigurationProperties(prefix = "cors")
public class CorsConfig {
    private List<String> allowedOrigins = Arrays.asList("http://localhost:3000", "http://localhost:8080");
    private List<String> allowedMethods = Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH");
    private List<String> allowedHeaders = Arrays.asList("*");
    private boolean allowCredentials = true;
    private long maxAge = 3600L;
}