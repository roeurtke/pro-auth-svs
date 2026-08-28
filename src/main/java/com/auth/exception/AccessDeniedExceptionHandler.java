package com.auth.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * @author Roeurt Kesei
 * Returns a JSON error when access is denied (authenticated but insufficient permissions).
 */
@Component
public class AccessDeniedExceptionHandler implements ServerAccessDeniedHandler {

    private final ObjectMapper objectMapper;
    private final ErrorResponseFactory errorResponseFactory;

    public AccessDeniedExceptionHandler(
        ObjectMapper objectMapper,
        ErrorResponseFactory errorResponseFactory
    ) {
        this.objectMapper = objectMapper;
        this.errorResponseFactory = errorResponseFactory;
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        ErrorResponse response = errorResponseFactory.create(
            HttpStatus.FORBIDDEN,
            "Forbidden",
            "You don't have permission to access this resource."
        );

        byte[] bytes;
        try {
            bytes = objectMapper.writeValueAsBytes(response);
        } catch (Exception e) {
            return Mono.error(e);
        }

        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(bytes)));
    }
}
