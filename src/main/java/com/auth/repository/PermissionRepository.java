package com.auth.repository;

import com.auth.model.Permission;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Collection;

/**
 * @author Roeurt Kesei
 * Repository for managing Permission entities.
 */
public interface PermissionRepository extends ReactiveCrudRepository<Permission, Long> {
    
    Mono<Permission> findByName(String name);
    Mono<Boolean> existsByName(String name);
    Mono<Permission> findByIdAndIsDeletedFalse(Long id);
    Flux<Permission> findByIdIn(Collection<Long> ids);

    @Query("SELECT * FROM tbl_permission " +
        "WHERE is_deleted = false " +
        "ORDER BY id " +
        "LIMIT :size OFFSET :offset")
    Flux<Permission> findAllByIsDeletedFalse(int size, long offset);

    @Query("SELECT COUNT(*) FROM tbl_permission WHERE is_deleted = false")
    Mono<Long> countByIsDeletedFalse();
}