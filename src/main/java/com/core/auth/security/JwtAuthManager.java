package com.core.auth.security;

import com.core.auth.service.RoleService;
import com.core.auth.service.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@Primary
@RequiredArgsConstructor
public class JwtAuthManager implements ReactiveAuthenticationManager {

    private final JwtTokenProvider jwtTokenProvider;
    private final TokenService tokenService;
    private final RoleService roleService;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        Object credentials = authentication.getCredentials();

        if (credentials == null) {
            return Mono.error(new BadCredentialsException("JWT token is missing"));
        }

        String token = credentials.toString();

        if (token.isBlank()) {
            return Mono.error(new BadCredentialsException("JWT token is missing"));
        }

        if (jwtTokenProvider.isTokenExpired(token)) {
            return Mono.error(new BadCredentialsException("JWT token expired"));
        }

        return tokenService.validateAccessToken(token)
                .flatMap(valid -> {
                    if (!valid) {
                        return Mono.error(new BadCredentialsException("JWT token is invalid or revoked"));
                    }

                    String username = jwtTokenProvider.getUsernameFromToken(token);
                    Long userId = jwtTokenProvider.getUserIdFromToken(token);

                    return roleService.getAuthoritiesForUser(userId)
                            .map(authorities -> {
                                log.debug("Authenticated user '{}' with authorities: {}", username, authorities);
                                return new UsernamePasswordAuthenticationToken(username, token, authorities);
                            });
                });
    }
}