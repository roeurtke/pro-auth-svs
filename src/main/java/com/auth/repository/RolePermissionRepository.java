package com.auth.repository;

import com.auth.model.RolePermission;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Collection;

/**
 * @author Roeurt Kesei
 * Repository for managing RolePermission entities.
 */
public interface RolePermissionRepository extends ReactiveCrudRepository<RolePermission, Long> {
    
    Flux<RolePermission> findPermissionByRoleId(Long roleId);

    Flux<RolePermission> findByRoleIdIn(Collection<Long> roleIds);

    default Mono<Void> deleteByRoleId(Long roleId) {
        return findPermissionByRoleId(roleId)
            .flatMap(this::delete)
            .then();
    }
}