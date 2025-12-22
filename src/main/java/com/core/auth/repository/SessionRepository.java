package com.core.auth.repository;

import com.core.auth.model.Session;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@Repository
public interface SessionRepository extends R2dbcRepository<Session, Long> {
    
    Mono<Session> findBySessionToken(String sessionToken);
    
    Flux<Session> findByUserId(String userId);
    
    Flux<Session> findByUserIdAndActiveTrue(String userId);
    
    @Query("SELECT * FROM tbl_session WHERE expires_at < :now AND active = true")
    Flux<Session> findExpiredSessions(LocalDateTime now);
    
    @Query("SELECT * FROM tbl_session WHERE last_activity_at < :threshold AND active = true")
    Flux<Session> findInactiveSessions(LocalDateTime threshold);
    
    @Query("SELECT COUNT(*) FROM tbl_session WHERE active = true")
    Mono<Long> countByActiveTrue();
    
    @Query("SELECT COUNT(DISTINCT user_id) FROM tbl_session WHERE active = true")
    Mono<Long> countDistinctUsersWithActiveSessions();
    
    @Query("SELECT AVG(EXTRACT(EPOCH FROM (last_activity_at - login_at))/60) FROM tbl_session WHERE active = false")
    Mono<Double> findAverageSessionDuration();
    
    // Add this method that SessionService needs
    @Query("SELECT COUNT(*) FROM tbl_session")
    Mono<Long> count();
}