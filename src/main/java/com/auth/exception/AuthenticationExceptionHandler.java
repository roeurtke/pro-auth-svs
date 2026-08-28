package com.auth.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author Roeurt Kesei
 * Returns a JSON error when authentication is required but missing/invalid.
 */
@Component
public class AuthenticationExceptionHandler implements ServerAuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    public AuthenticationExceptionHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Commences the authentication process by returning a JSON error response when authentication is required but missing or invalid.
     *
     * @param exchange the current server exchange
     * @param ex the authentication exception that triggered this entry point
     * @return a Mono that completes when the response is written
     */
    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        boolean hasAccessToken = hasAccessToken(exchange);
        // A request without credentials needs a login prompt. If credentials
        // were supplied, preserve the specific validation failure.
        String message = hasAccessToken && ex != null && ex.getMessage() != null
                ? ex.getMessage()
                : "Authentication required. Please login first.";

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", HttpStatus.UNAUTHORIZED.value());
        response.put("error", "Access Denied");
        response.put("message", message);
        response.put("timestamp", LocalDateTime.now().toString());

        byte[] bytes;
        try {
            bytes = objectMapper.writeValueAsBytes(response);
        } catch (Exception e) {
            // Never let a serialization failure escape the security filter chain.
            String fallback = "{\"error\":\"Access Denied\","
                    + "\"message\":\"Authentication required. Please login first.\","
                    + "\"status\":401}";
            bytes = fallback.getBytes(StandardCharsets.UTF_8);
        }

        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
    }

    /**
     * Checks if the request has an access token either in the Authorization header or as a query parameter.
     *
     * @param exchange the current server exchange
     * @return true if an access token is present, false otherwise
     */
    private boolean hasAccessToken(ServerWebExchange exchange) {
        String authorization = exchange.getRequest().getHeaders().getFirst("Authorization");
        return (authorization != null && authorization.startsWith("Bearer ")
                && !authorization.substring(7).isBlank())
                || exchange.getRequest().getQueryParams().getFirst("token") != null;
    }
}