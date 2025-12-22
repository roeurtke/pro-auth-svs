package com.core.auth.repository;

import com.core.auth.model.Token;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@Repository
public interface TokenRepository extends R2dbcRepository<Token, Long> {
    
    Mono<Token> findByToken(String token);
    
    // Add this method for Long userId
    @Query("SELECT * FROM tbl_token WHERE user_id = :userId")
    Flux<Token> findAllByUserId(Long userId);
    
    // Keep this for String userId if needed elsewhere
    @Query("SELECT * FROM tbl_token WHERE user_id = :userId")
    Flux<Token> findByUserId(String userId);
    
    Flux<Token> findByUserIdAndTokenType(String userId, String tokenType);
    
    @Modifying
    @Query("UPDATE tbl_token SET revoked = true, revoked_at = :revokedAt WHERE user_id = :userId AND token_type = :tokenType AND revoked = false")
    Mono<Void> revokeAllUserTokens(String userId, String tokenType, LocalDateTime revokedAt);
    
    @Modifying
    @Query("DELETE FROM tbl_token WHERE expires_at < :date")
    Mono<Void> deleteExpiredTokens(LocalDateTime date);
    
    // Add this method that TokenService.validateRefreshToken() uses
    Mono<Boolean> existsByTokenAndRevokedFalseAndExpiredFalse(String token);
}