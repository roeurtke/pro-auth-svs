package com.auth.repository;

import com.auth.model.UserRole;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * @author Roeurt Kesei
 * Repository for managing UserRole entities.
 */
public interface UserRoleRepository extends ReactiveCrudRepository<UserRole, Void> {

    // Find roles by user
    Flux<UserRole> findByUserId(Long userId);

    // Delete a specific role for a user
    Mono<Void> deleteByUserIdAndRoleId(Long userId, Long roleId);

    // Delete all roles for a user
    @Query("DELETE FROM tbl_user_role WHERE user_id = :userId")
    Mono<Void> deleteByUserId(Long userId);

    // Custom insert query for assigning a role
    @Query("INSERT INTO tbl_user_role (user_id, role_id) VALUES (:userId, :roleId)")
    Mono<Void> insertUserRole(Long userId, Long roleId);
}
