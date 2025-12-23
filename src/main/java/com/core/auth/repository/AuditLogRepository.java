package com.core.auth.repository;

import com.core.auth.model.AuditLog;
import org.springframework.data.domain.Pageable;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;

import java.time.LocalDateTime;

@Repository
public interface AuditLogRepository extends R2dbcRepository<AuditLog, Long> {
    
    Flux<AuditLog> findByUserId(Long userId, Pageable pageable);
    Flux<AuditLog> findByAction(String action, Pageable pageable);
    Flux<AuditLog> findByResourceType(String resourceType, Pageable pageable);
    
    @Query("SELECT * FROM tbl_audit_log WHERE timestamp BETWEEN :startDate AND :endDate ORDER BY timestamp DESC")
    Flux<AuditLog> findByTimestampBetween(LocalDateTime startDate, LocalDateTime endDate, Pageable pageable);
    
    @Query("SELECT * FROM tbl_audit_log WHERE user_id = :userId AND timestamp BETWEEN :startDate AND :endDate ORDER BY timestamp DESC")
    Flux<AuditLog> findByUserIdAndTimestampBetween(Long userId, LocalDateTime startDate, LocalDateTime endDate, Pageable pageable);
}