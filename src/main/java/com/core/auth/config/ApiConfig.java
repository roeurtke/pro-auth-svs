package com.core.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "api")
public class ApiConfig {
    private String basePath = "/api/v1";
    
    public String getAuthPath() {
        return basePath + "/auth";
    }
    
    public String getUserPath() {
        return basePath + "/users";
    }
    
    public String getAdminPath() {
        return basePath + "/admin";
    }
    
    public String getRolePath() {
        return basePath + "/roles";
    }
    
    public String getPermissionPath() {
        return basePath + "/permissions";
    }
    
    public String getSwaggerPath() {
        return basePath + "/docs";
    }
}