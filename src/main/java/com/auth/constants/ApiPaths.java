package com.auth.constants;

import org.springframework.stereotype.Component;
import com.auth.config.ApiConfig;

/**
 * @author Roeurt Kesei
 * Centralized API path definitions.
 */
@Component
public class ApiPaths {

    private final ApiConfig api;

    public ApiPaths(ApiConfig apiConfig) {
        this.api = apiConfig;
    }

    public String base() { return api.getBase(); }

    public String auth() { return api.getBase() + "/auth_mod/**"; }
    public String users() { return api.getBase() + "/user_mod/users/**"; }
    public String roles() { return api.getBase() + "/user_mod/roles/**"; }
    public String permissions() { return api.getBase() + "/user_mod/permissions/**"; }

    // Swagger
    public static final String SWAGGER_UI = "/swagger-ui/**";
    public static final String SWAGGER_HTML = "/swagger-ui.html";
    public static final String API_DOCS = "/v3/api-docs/**";
    public static final String API_DOCS_BASE = "/v3/api-docs";
}
