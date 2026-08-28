package com.auth.repository;

import com.auth.model.Role;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * @author Roeurt Kesei
 * Repository for managing Role entities.
 */
public interface RoleRepository extends ReactiveCrudRepository<Role, Long> {
    
    Mono<Role> findByName(String name);
    Mono<Boolean> existsByName(String name);
    Mono<Role> findByIdAndIsDeletedFalse(Long id);
    reactor.core.publisher.Flux<Role> findAllByIsDeletedFalse();
}