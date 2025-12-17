package com.core.auth.repository;

import lombok.RequiredArgsConstructor;
import com.core.auth.security.JwtAuthManager;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class JwtSecurityContextRepository implements ServerSecurityContextRepository {
    
    private static final String TOKEN_PREFIX = "Bearer ";
    
    private final JwtAuthManager jwtAuthManager;
    
    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        return Mono.empty();
    }
    
    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        return Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                .filter(authHeader -> authHeader.startsWith(TOKEN_PREFIX))
                .map(authHeader -> authHeader.substring(TOKEN_PREFIX.length()))
                .flatMap(token -> {
                    Authentication auth = new UsernamePasswordAuthenticationToken(
                            token,
                            token
                    );
                    return jwtAuthManager.authenticate(auth)
                            .map(SecurityContextImpl::new);
                });
    }
}