package com.core.auth.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
@Primary
@RequiredArgsConstructor
public class JwtAuthManager implements ReactiveAuthenticationManager {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.just(authentication)
                .flatMap(auth -> {
                    String token = auth.getCredentials().toString();

                    if (jwtTokenProvider.isTokenExpired(token)) {
                        return Mono.error(new BadCredentialsException("JWT token expired"));
                    }

                    String username = jwtTokenProvider.getUsernameFromToken(token);
                    List<String> authorities = jwtTokenProvider.getAuthoritiesFromToken(token);

                    List<SimpleGrantedAuthority> grantedAuthorities = authorities.stream()
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());

                    return Mono.just(new UsernamePasswordAuthenticationToken(
                            username,
                            token,
                            grantedAuthorities
                    ));
                });
    }
}