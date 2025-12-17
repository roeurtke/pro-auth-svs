package com.core.auth.repository;

import com.core.auth.model.Role;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Repository
public interface RoleRepository extends R2dbcRepository<Role, Long> {
    
    Mono<Role> findByName(String name);
    Mono<Role> findByCode(String code);
    
    @Query("SELECT r.* FROM tbl_role r " +
        "JOIN tbl_user_role ur ON r.id = ur.role_id " +
        "WHERE ur.user_id = :userId")
    Flux<Role> findByUserId(Long userId);
    
    Mono<Boolean> existsByName(String name);
    Mono<Boolean> existsByCode(String code);
}