package com.core.auth.repository;

import com.core.auth.model.User;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Repository
public interface UserRepository extends R2dbcRepository<User, Long> {
    
    Mono<User> findByUsername(String username);
    Mono<User> findByEmail(String email);
    Mono<User> findByUsernameOrEmail(String username, String email);
    
    @Query("SELECT u.* FROM tbl_user u " +
        "JOIN tbl_user_role ur ON u.id = ur.user_id " +
        "WHERE ur.role_id = :roleId")
    Flux<User> findByRoleId(Long roleId);
    
    Mono<Boolean> existsByUsername(String username);
    Mono<Boolean> existsByEmail(String email);
    
    @Query("SELECT u.* FROM tbl_user u WHERE u.username = :username OR u.email = :email")
    Mono<User> findUserWithCredentials(String username, String email);
}