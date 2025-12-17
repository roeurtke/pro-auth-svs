package com.core.auth.repository;

import com.core.auth.model.Permission;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Repository
public interface PermissionRepository extends R2dbcRepository<Permission, Long> {
    
    Mono<Permission> findByCode(String code);
    
    @Query("SELECT p.* FROM tbl_permission p " +
        "JOIN tbl_role_permission rp ON p.id = rp.permission_id " +
        "WHERE rp.role_id = :roleId")
    Flux<Permission> findByRoleId(Long roleId);
    
    @Query("SELECT p.* FROM tbl_permission p " +
        "JOIN tbl_role_permission rp ON p.id = rp.permission_id " +
        "JOIN tbl_user_role ur ON rp.role_id = ur.role_id " +
        "WHERE ur.user_id = :userId")
    Flux<Permission> findByUserId(Long userId);
    
    Flux<Permission> findByCategory(String category);
}