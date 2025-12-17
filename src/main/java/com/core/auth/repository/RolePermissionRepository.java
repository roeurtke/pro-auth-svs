package com.core.auth.repository;

import com.core.auth.model.RolePermission;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Repository
public interface RolePermissionRepository extends R2dbcRepository<RolePermission, Long> {
    
    Flux<RolePermission> findByRoleId(Long roleId);
    Flux<RolePermission> findByPermissionId(Long permissionId);
    
    Mono<RolePermission> findByRoleIdAndPermissionId(Long roleId, Long permissionId);
    
    @Modifying
    @Query("DELETE FROM tbl_role_permission WHERE role_id = :roleId AND permission_id = :permissionId")
    Mono<Void> deleteByRoleIdAndPermissionId(Long roleId, Long permissionId);
    
    @Modifying
    @Query("DELETE FROM tbl_role_permission WHERE role_id = :roleId")
    Mono<Void> deleteByRoleId(Long roleId);
}