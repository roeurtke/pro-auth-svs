package com.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * @author Roeurt Kesei
 * Configuration class for API properties.
 */
@Configuration
@ConfigurationProperties(prefix = "api")
public class ApiConfig {

    private String base;

    public String getBase() { return base; }
    public void setBase(String base) { this.base = base; }
}
