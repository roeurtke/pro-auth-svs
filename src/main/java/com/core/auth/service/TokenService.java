package com.core.auth.service;

import com.core.auth.exception.TokenException;
import com.core.auth.model.Token;
import com.core.auth.repository.TokenRepository;
import com.core.auth.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final TokenRepository tokenRepository;
    private final JwtTokenProvider jwtTokenProvider;

    public Mono<Token> validateRefreshToken(String refreshToken) {
        try {
            if (jwtTokenProvider.isTokenExpired(refreshToken)) {
                return Mono.error(new TokenException("Refresh token expired"));
            }

            return tokenRepository.findByToken(refreshToken)
                    .filter(Token::isValid)
                    .switchIfEmpty(Mono.error(new TokenException("Invalid refresh token")));
        } catch (Exception e) {
            return Mono.error(new TokenException("Invalid refresh token"));
        }
    }

    public Mono<Void> revokeToken(String token) {
        return tokenRepository.findByToken(token)
                .flatMap(t -> {
                    t.setRevoked(true);
                    t.setRevokedAt(LocalDateTime.now());
                    return tokenRepository.save(t).then();
                })
                .switchIfEmpty(Mono.empty());
    }

    public Mono<Void> saveRefreshToken(String userId, String refreshToken) {
        // Convert userId from String to Long
        Long userIdLong;
        try {
            userIdLong = Long.parseLong(userId);
        } catch (NumberFormatException e) {
            return Mono.error(new IllegalArgumentException("Invalid user ID: " + userId));
        }
        
        LocalDateTime expiresAt = jwtTokenProvider.getExpirationDateFromToken(refreshToken);
        Token token = Token.builder()
                .userId(userIdLong)
                .token(refreshToken)
                .tokenType("REFRESH")
                .revoked(false)
                .expired(false)
                .createdAt(LocalDateTime.now())
                .expiresAt(expiresAt)
                .revokedAt(null)
                .build();

        return tokenRepository.save(token).then();
    }
    
    public Mono<Void> revokeAllUserTokens(String userId) {
        // Convert userId from String to Long for the query
        Long userIdLong;
        try {
            userIdLong = Long.parseLong(userId);
        } catch (NumberFormatException e) {
            return Mono.error(new IllegalArgumentException("Invalid user ID: " + userId));
        }
        
        LocalDateTime now = LocalDateTime.now();
        return tokenRepository.findAllByUserId(userIdLong)
                .flatMap(token -> {
                    token.setRevoked(true);
                    token.setRevokedAt(now);
                    return tokenRepository.save(token);
                })
                .then();
    }
}
