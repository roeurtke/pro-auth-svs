package com.auth.repository;

import com.auth.model.UserActivity;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

public interface UserActivityRepository extends ReactiveCrudRepository<UserActivity, Long> {

    @Query("SELECT * FROM tbl_user_activity WHERE (:userId IS NULL OR user_id = :userId) "
        + "ORDER BY created_at DESC LIMIT :size OFFSET :offset")
    Flux<UserActivity> findRecent(Long userId, int size, long offset);

    @Query("SELECT COUNT(*) FROM tbl_user_activity WHERE (:userId IS NULL OR user_id = :userId)")
    reactor.core.publisher.Mono<Long> count(Long userId);
}