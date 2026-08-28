package com.auth.service;

import com.auth.model.UserActivity;
import com.auth.repository.UserActivityRepository;
import com.auth.repository.UserRepository;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

/**
 * @author Roeurt Kesei
 * Service for handling user activity and audit events.
 */
@Service
public class UserActivityService {

    private final UserActivityRepository activityRepository;
    private final UserRepository userRepository;

    public UserActivityService(UserActivityRepository activityRepository, UserRepository userRepository) {
        this.activityRepository = activityRepository;
        this.userRepository = userRepository;
    }

    public Mono<Void> record(UserActivity activity) {
        if (activity.getCreatedAt() == null) {
            activity.setCreatedAt(LocalDateTime.now());
        }
        if (activity.getSuccessful() == null) {
            activity.setSuccessful(true);
        }
        return activityRepository.save(activity)
            .onErrorResume(error -> Mono.empty())
            .then();
    }

    public Mono<Void> recordAuth(String eventType, Long userId, String username, boolean successful) {
        return record(UserActivity.builder()
            .userId(userId)
            .username(username)
            .eventType(eventType)
            .successful(successful)
            .build());
    }

    public Mono<Void> recordUserChange(String eventType, Long actorId, Long targetUserId) {
        return record(UserActivity.builder()
            .userId(actorId)
            .targetUserId(targetUserId)
            .eventType(eventType)
            .build());
    }

    public Mono<Void> updateLastActive(Long userId) {
        return userRepository.updateLastActiveAt(userId)
            .onErrorResume(error -> Mono.empty())
            .then();
    }

    public Mono<Long> count(Long userId) {
        return activityRepository.count(userId).onErrorReturn(0L);
    }

    public reactor.core.publisher.Flux<UserActivity> findRecent(Long userId, int size, long offset) {
        return activityRepository.findRecent(userId, size, offset);
    }
}