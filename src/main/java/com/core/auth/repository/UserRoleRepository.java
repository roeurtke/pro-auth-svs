package com.core.auth.repository;

import com.core.auth.model.UserRole;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Repository
public interface UserRoleRepository extends R2dbcRepository<UserRole, Long> {
    
    Flux<UserRole> findByUserId(Long userId);
    Flux<UserRole> findByRoleId(Long roleId);
    
    Mono<UserRole> findByUserIdAndRoleId(Long userId, Long roleId);
    
    @Modifying
    @Query("DELETE FROM tbl_user_role WHERE user_id = :userId AND role_id = :roleId")
    Mono<Void> deleteByUserIdAndRoleId(Long userId, Long roleId);
    
    @Modifying
    @Query("DELETE FROM tbl_user_role WHERE user_id = :userId")
    Mono<Void> deleteByUserId(Long userId);
    
    @Modifying
    @Query("DELETE FROM tbl_user_role WHERE role_id = :roleId")
    Mono<Void> deleteByRoleId(Long roleId);
}