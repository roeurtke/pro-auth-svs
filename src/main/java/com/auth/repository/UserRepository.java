package com.auth.repository;

import com.auth.model.User;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * @author Roeurt Kesei
 * Repository for managing User entities.
 */
public interface UserRepository extends ReactiveCrudRepository<User, Long> {
    
    Mono<User> findByUsername(String username);
    
    Mono<User> findByEmail(String email);
    
    // Find only non-deleted users
    Mono<User> findByUsernameAndIsDeletedFalse(String username);

    Mono<User> findByEmailAndIsDeletedFalse(String email);

    @Query("SELECT * FROM tbl_user " +
        "WHERE is_deleted = false " +
        "ORDER BY id " +
        "LIMIT :size OFFSET :offset")
    Flux<User> findAllByIsDeletedFalse(int size, long offset);

    @Query("SELECT COUNT(*) FROM tbl_user WHERE is_deleted = false")
    Mono<Long> countByIsDeletedFalse();

    Mono<User> findByIdAndIsDeletedFalse(Long id);
    
    Mono<Boolean> existsByUsername(String username);
    Mono<Boolean> existsByUsernameAndIsDeletedFalse(String username);
    
    Mono<Boolean> existsByEmail(String email);
    Mono<Boolean> existsByEmailAndIsDeletedFalse(String email);
    
    @Query("SELECT u.*, r.id as role_id, r.name as role_name, r.description as role_description " +
        "FROM tbl_user u " +
        "LEFT JOIN tbl_user_role ur ON u.id = ur.user_id " +
        "LEFT JOIN tbl_role r ON ur.role_id = r.id " +
        "WHERE u.username = :username AND u.is_deleted = false")
    Mono<User> findByUsernameWithRoles(String username);
}