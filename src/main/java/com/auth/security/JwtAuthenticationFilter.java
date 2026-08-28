package com.auth.security;

import com.auth.service.JwtService;
import com.auth.service.UserService;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * @author Roeurt Kesei
 * JWT Authentication Filter for extracting and validating JWT tokens from HTTP requests.
 */
@Component
public class JwtAuthenticationFilter implements ServerAuthenticationConverter {
    
    private final JwtService jwtService;
    private final UserService userService;
    
    /**
     * Constructs a JwtAuthenticationFilter with the provided JwtService and UserService.
     *
     * @param jwtService the service for handling JWT operations
     * @param userService the service for user-related operations
     */
    public JwtAuthenticationFilter(JwtService jwtService, UserService userService) {
        this.jwtService = jwtService;
        this.userService = userService;
    }
    
    /**
     * Converts the incoming ServerWebExchange into an Authentication object by extracting and validating the JWT token.
     *
     * @param exchange the current server exchange
     * @return a Mono emitting the Authentication object if successful, or an error if validation fails
     */
    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        return extractTokenFromRequest(exchange)
                .flatMap(this::validate)
                .flatMap(token -> {
                    String username = jwtService.extractUsername(token);
                    return userService.findByUsername(username)
                            .map(userDetails -> new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    token,
                                    userDetails.getAuthorities()
                            ));
                });
    }

    /**
     * Validates the provided JWT token.
     *
     * @param token the JWT token to validate
     * @return a Mono emitting the token if valid, or an error if invalid
     */
    private Mono<String> validate(String token) {
        try {
            if (Boolean.TRUE.equals(jwtService.validateToken(token))) {
                return Mono.just(token);
            }
            return Mono.error(new BadCredentialsException("Authentication required. Please login first."));
        } catch (RuntimeException ex) {
            return Mono.error(new BadCredentialsException(ex.getMessage(), ex));
        }
    }

    /**
     * Extracts the JWT token from the Authorization header or query parameter of the request.
     *
     * @param exchange the current server exchange
     * @return a Mono emitting the extracted token, or empty if no token is found
     */
    private Mono<String> extractTokenFromRequest(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return Mono.just(authHeader.substring(7));
        }
        String tokenParam = exchange.getRequest().getQueryParams().getFirst("token");
        if (tokenParam != null) {
            return Mono.just(tokenParam);
        }
        return Mono.empty();
    }
}