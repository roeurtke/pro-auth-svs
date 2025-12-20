package com.core.auth.service;

import com.core.auth.exception.SessionNotFoundException;
import com.core.auth.model.Session;
import com.core.auth.repository.SessionRepository;
import com.core.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.Data;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class SessionService {

    private final SessionRepository sessionRepository;
    private final UserRepository userRepository;
    private final AuditLogService auditLogService;

    @Value("${session.timeout.minutes:30}")
    private int sessionTimeoutMinutes;

    @Value("${session.max.concurrent:5}")
    private int maxConcurrentSessions;

    /**
     * Create a new session for a user
     */
    @Transactional
    public Mono<Session> createSession(String userId, String ipAddress, String userAgent) {
        log.info("Creating session for user: {}, IP: {}", userId, ipAddress);

        return userRepository.findById(Long.parseLong(userId))
                .switchIfEmpty(Mono.error(new RuntimeException("User not found: " + userId)))
                .flatMap(user -> {
                    String sessionToken = generateSessionToken();

                    Session session = Session.builder()
                            .userId(userId)
                            .sessionToken(sessionToken)
                            .ipAddress(ipAddress)
                            .userAgent(userAgent)
                            .deviceInfo(extractDeviceInfo(userAgent))
                            .location("Unknown")
                            .loginAt(LocalDateTime.now())
                            .lastActivityAt(LocalDateTime.now())
                            .expiresAt(LocalDateTime.now().plusMinutes(sessionTimeoutMinutes))
                            .active(true)
                            .build();

                    return sessionRepository.save(session)
                            .doOnSuccess(savedSession ->
                                    log.info("Session created: {} for user: {}", savedSession.getId(), userId)
                            );
                })
                .doOnSuccess(session ->
                        auditLogService.logSessionCreation(userId, session.getId().toString(), ipAddress)
                );
    }

    /**
     * Validate and refresh a session
     */
    @Transactional
    public Mono<Session> validateAndRefreshSession(String sessionToken, String ipAddress) {
        log.debug("Validating session token: {}", sessionToken);

        return sessionRepository.findBySessionToken(sessionToken)
                .switchIfEmpty(Mono.error(new SessionNotFoundException(sessionToken)))
                .flatMap(session -> {
                    if (!session.isActive()) {
                        return Mono.error(new RuntimeException("Session is not active"));
                    }

                    if (session.getExpiresAt().isBefore(LocalDateTime.now())) {
                        log.info("Session expired: {}", session.getId());
                        session.setActive(false);
                        session.setLogoutReason("Session expired");
                        session.setLogoutAt(LocalDateTime.now());
                        return sessionRepository.save(session)
                                .flatMap(s -> Mono.error(new RuntimeException("Session expired")));
                    }

                    session.setLastActivityAt(LocalDateTime.now());

                    if (Duration.between(LocalDateTime.now(), session.getExpiresAt()).toMinutes() < 5) {
                        session.setExpiresAt(LocalDateTime.now().plusMinutes(sessionTimeoutMinutes));
                        log.debug("Extended session: {}", session.getId());
                    }

                    if (!session.getIpAddress().equals(ipAddress)) {
                        log.info("IP address changed for session {}: {} -> {}", session.getId(), session.getIpAddress(), ipAddress);
                        String oldIp = session.getIpAddress();
                        session.setIpAddress(ipAddress);

                        auditLogService.logSessionIpChange(session.getUserId(), session.getId().toString(), oldIp, ipAddress);
                    }

                    return sessionRepository.save(session);
                })
                .doOnSuccess(session -> log.debug("Session validated: {}", session.getId()))
                .doOnError(error -> log.warn("Session validation failed: {}", error.getMessage()));
    }

    /**
     * Logout from all active sessions for a user
     */
    @Transactional
    public Mono<Void> logout(String userId, String ipAddress) {
        log.info("Logging out user: {} from IP: {}", userId, ipAddress);

        return sessionRepository.findByUserIdAndActiveTrue(userId)
                .flatMap(session -> {
                    session.setActive(false);
                    session.setLogoutAt(LocalDateTime.now());
                    session.setLogoutReason("User initiated logout");
                    return sessionRepository.save(session);
                })
                .then()
                .doOnSuccess(v -> auditLogService.logLogout(userId, ipAddress));
    }

    /**
     * Logout a specific session by token
     */
    @Transactional
    public Mono<Void> logoutByToken(String sessionToken, String reason) {
        log.info("Logging out session: {}, reason: {}", sessionToken, reason);

        return sessionRepository.findBySessionToken(sessionToken)
                .switchIfEmpty(Mono.error(new SessionNotFoundException(sessionToken)))
                .flatMap(session -> {
                    session.setActive(false);
                    session.setLogoutAt(LocalDateTime.now());
                    session.setLogoutReason(reason);

                    return sessionRepository.save(session)
                            .doOnSuccess(s -> auditLogService.logSessionLogout(session.getUserId(), session.getId().toString(), reason))
                            .then();
                });
    }

    /**
     * Get all sessions for a user
     */
    @Transactional(readOnly = true)
    public Flux<Session> getUserSessions(String userId) {
        return sessionRepository.findByUserId(userId)
                .sort((s1, s2) -> s2.getLastActivityAt().compareTo(s1.getLastActivityAt()));
    }

    /**
     * Get active sessions for a user
     */
    @Transactional(readOnly = true)
    public Flux<Session> getActiveUserSessions(String userId) {
        return sessionRepository.findByUserIdAndActiveTrue(userId);
    }

    /**
     * Terminate all sessions for a user
     */
    @Transactional
    public Mono<Void> terminateAllUserSessions(String userId, String terminatedBy, String reason) {
        log.info("Terminating all sessions for user: {}, by: {}, reason: {}", userId, terminatedBy, reason);

        return sessionRepository.findByUserIdAndActiveTrue(userId)
                .flatMap(session -> {
                    session.setActive(false);
                    session.setLogoutAt(LocalDateTime.now());
                    session.setLogoutReason(reason + " (Terminated by: " + terminatedBy + ")");
                    return sessionRepository.save(session);
                })
                .then()
                .doOnSuccess(v -> auditLogService.logSessionTermination(terminatedBy, userId, "ALL", reason));
    }

    /**
     * Terminate a specific session
     */
    @Transactional
    public Mono<Void> terminateSession(Long sessionId, String terminatedBy, String reason) {
        log.info("Terminating session: {}, by: {}, reason: {}", sessionId, terminatedBy, reason);

        return sessionRepository.findById(sessionId)
                .switchIfEmpty(Mono.error(new SessionNotFoundException(sessionId)))
                .flatMap(session -> {
                    session.setActive(false);
                    session.setLogoutAt(LocalDateTime.now());
                    session.setLogoutReason(reason + " (Terminated by: " + terminatedBy + ")");
                    return sessionRepository.save(session)
                            .doOnSuccess(s -> auditLogService.logSessionTermination(terminatedBy, session.getUserId(), sessionId.toString(), reason))
                            .then();
                });
    }

    /**
     * Enforce concurrent session limit
     */
    @Transactional
    public Mono<Boolean> enforceConcurrentSessionLimit(String userId) {
        return getActiveUserSessions(userId)
                .collectList()
                .flatMap(activeSessions -> {
                    if (activeSessions.size() >= maxConcurrentSessions) {
                        activeSessions.sort((s1, s2) -> s1.getLastActivityAt().compareTo(s2.getLastActivityAt()));
                        Session oldestSession = activeSessions.get(0);
                        return terminateSession(oldestSession.getId(), "SYSTEM", "Concurrent session limit exceeded")
                                .thenReturn(true);
                    }
                    return Mono.just(false);
                });
    }

    /**
     * Clean up expired sessions (reactive scheduled task)
     */
    @Scheduled(cron = "0 */5 * * * *") // every 5 minutes
    public Mono<Void> cleanupExpiredSessionsReactive() {
        log.debug("Cleaning up expired sessions...");

        return sessionRepository.findExpiredSessions(LocalDateTime.now())
                .flatMap(session -> {
                    log.debug("Cleaning up expired session: {}", session.getId());
                    session.setActive(false);
                    session.setLogoutAt(LocalDateTime.now());
                    session.setLogoutReason("Session expired (auto cleanup)");
                    return sessionRepository.save(session);
                })
                .then()
                .doOnSuccess(v -> log.debug("Expired session cleanup completed"))
                .doOnError(e -> log.error("Error cleaning up expired sessions", e));
    }

    /**
     * Clean up inactive sessions (reactive scheduled task)
     */
    @Scheduled(cron = "0 0 */1 * * *") // every hour
    public Mono<Void> cleanupInactiveSessionsReactive() {
        log.debug("Cleaning up inactive sessions...");

        LocalDateTime threshold = LocalDateTime.now().minusHours(24);
        return sessionRepository.findInactiveSessions(threshold)
                .flatMap(session -> {
                    log.debug("Cleaning up inactive session: {}", session.getId());
                    session.setActive(false);
                    session.setLogoutAt(LocalDateTime.now());
                    session.setLogoutReason("Session inactive for 24 hours");
                    return sessionRepository.save(session);
                })
                .then()
                .doOnSuccess(v -> log.debug("Inactive session cleanup completed"))
                .doOnError(e -> log.error("Error cleaning up inactive sessions", e));
    }

    /**
     * Get session statistics
     */
    @Transactional(readOnly = true)
    public Mono<SessionStats> getSessionStats() {
        return Mono.zip(
                sessionRepository.count(),
                sessionRepository.countByActiveTrue(),
                sessionRepository.countDistinctUsersWithActiveSessions(),
                sessionRepository.findAverageSessionDuration()
        ).map(tuple -> SessionStats.builder()
                .totalSessions(tuple.getT1())
                .activeSessions(tuple.getT2())
                .activeUsers(tuple.getT3())
                .averageDurationMinutes(tuple.getT4())
                .build()
        );
    }

    // Helper methods
    private String generateSessionToken() {
        return UUID.randomUUID().toString().replace("-", "") + "-" + System.currentTimeMillis();
    }

    private String extractDeviceInfo(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) return "Unknown";
        if (userAgent.contains("Mobile")) return "Mobile";
        if (userAgent.contains("Tablet")) return "Tablet";
        if (userAgent.contains("Windows")) return "Windows PC";
        if (userAgent.contains("Mac")) return "Mac";
        if (userAgent.contains("Linux")) return "Linux PC";
        return "Desktop";
    }

    // Statistics DTO
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SessionStats {
        private Long totalSessions;
        private Long activeSessions;
        private Long activeUsers;
        private Double averageDurationMinutes;
    }
}
