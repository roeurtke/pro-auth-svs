package com.core.auth.service;

import com.core.auth.model.AuditLog;
import com.core.auth.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditLogService {
    
    private final AuditLogRepository auditLogRepository;
    
    // Main log method accepts Long userId
    public Mono<AuditLog> log(Long userId, String action, String resourceType, 
                        String resourceId, String oldValue, String newValue,
                        String ipAddress, String userAgent, boolean success, 
                        String errorMessage) {
        AuditLog auditLog = AuditLog.builder()
                .userId(userId)
                .action(action)
                .resourceType(resourceType)
                .resourceId(resourceId)
                .oldValue(oldValue)
                .newValue(newValue)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .success(success)
                .errorMessage(errorMessage)
                .timestamp(LocalDateTime.now())
                .build();
        
        return auditLogRepository.save(auditLog)
                .doOnError(e -> log.error("Failed to save audit log", e));
    }
    
    // Overloaded method for String userId (for backward compatibility)
    public Mono<AuditLog> log(String userIdStr, String action, String resourceType, 
                        String resourceId, String oldValue, String newValue,
                        String ipAddress, String userAgent, boolean success, 
                        String errorMessage) {
        Long userId = null;
        if (userIdStr != null) {
            try {
                userId = Long.parseLong(userIdStr);
            } catch (NumberFormatException e) {
                log.warn("Invalid user ID format: {}", userIdStr);
                // userId remains null for non-numeric IDs like "SYSTEM"
            }
        }
        return log(userId, action, resourceType, resourceId, oldValue, newValue,
                ipAddress, userAgent, success, errorMessage);
    }
    
    // Existing methods updated for Long userId
    public Mono<AuditLog> logLoginSuccess(String username, String ipAddress, String userAgent) {
        return log((Long)null, "LOGIN_SUCCESS", "USER", username, null, null,
                ipAddress, userAgent, true, null);
    }
    
    public Mono<AuditLog> logLoginFailure(String username, String ipAddress, String userAgent, String error) {
        return log((Long)null, "LOGIN_FAILURE", "USER", username, null, null,
                ipAddress, userAgent, false, error);
    }
    
    public Mono<AuditLog> logLogout(String userId, String ipAddress) {
        Long userIdLong = parseUserId(userId);
        return log(userIdLong, "LOGOUT", "USER", userId, null, null,
                ipAddress, null, true, null);
    }
    
    public Mono<AuditLog> logRegistration(String username) {
        return log((Long)null, "REGISTRATION", "USER", username, null, null,
                null, null, true, null);
    }
    
    public Mono<AuditLog> logPasswordChange(Long userId) {
        return log(userId, "PASSWORD_CHANGE", "USER", userId.toString(),
                null, null, null, null, true, null);
    }
    
    public Mono<AuditLog> logUserUpdate(Long userId, String description) {
        return log(userId, "USER_UPDATE", "USER", userId.toString(),
                null, description, null, null, true, null);
    }
    
    public Mono<AuditLog> logUserEnable(Long userId) {
        return log(userId, "USER_ENABLE", "USER", userId.toString(),
                "DISABLED", "ENABLED", null, null, true, null);
    }
    
    public Mono<AuditLog> logUserDisable(Long userId) {
        return log(userId, "USER_DISABLE", "USER", userId.toString(),
                "ENABLED", "DISABLED", null, null, true, null);
    }
    
    public Mono<AuditLog> logUserLock(Long userId) {
        return log(userId, "USER_LOCK", "USER", userId.toString(),
                "UNLOCKED", "LOCKED", null, null, true, null);
    }
    
    public Mono<AuditLog> logUserUnlock(Long userId) {
        return log(userId, "USER_UNLOCK", "USER", userId.toString(),
                "LOCKED", "UNLOCKED", null, null, true, null);
    }
    
    public Mono<AuditLog> logRoleCreation(Long roleId, String roleName) {
        return log((Long)null, "ROLE_CREATE", "ROLE", roleId.toString(),
                null, roleName, null, null, true, null);
    }
    
    public Mono<AuditLog> logRoleUpdate(Long roleId, String description) {
        return log((Long)null, "ROLE_UPDATE", "ROLE", roleId.toString(),
                null, description, null, null, true, null);
    }
    
    public Mono<AuditLog> logRoleDeletion(Long roleId, String roleName) {
        return log((Long)null, "ROLE_DELETE", "ROLE", roleId.toString(),
                roleName, null, null, null, true, null);
    }
    
    public Mono<AuditLog> logRoleAssignment(Long userId, Long roleId) {
        return log((Long)null, "ROLE_ASSIGN", "USER_ROLE", userId + ":" + roleId,
                null, "ASSIGNED", null, null, true, null);
    }
    
    public Mono<AuditLog> logRoleRemoval(Long userId, Long roleId) {
        return log((Long)null, "ROLE_REMOVE", "USER_ROLE", userId + ":" + roleId,
                "ASSIGNED", null, null, null, true, null);
    }
    
    public Mono<AuditLog> logPermissionCreation(Long permissionId, String permissionName) {
        return log((Long)null, "PERMISSION_CREATE", "PERMISSION", permissionId.toString(),
                null, permissionName, null, null, true, null);
    }
    
    public Mono<AuditLog> logPermissionUpdate(Long permissionId, String description) {
        return log((Long)null, "PERMISSION_UPDATE", "PERMISSION", permissionId.toString(),
                null, description, null, null, true, null);
    }
    
    public Mono<AuditLog> logPermissionDeletion(Long permissionId, String permissionName) {
        return log((Long)null, "PERMISSION_DELETE", "PERMISSION", permissionId.toString(),
                permissionName, null, null, null, true, null);
    }
    
    public Mono<AuditLog> logPermissionsAssignment(Long roleId, Set<Long> permissionIds) {
        return log((Long)null, "PERMISSIONS_ASSIGN", "ROLE_PERMISSION", roleId.toString(),
                null, permissionIds.toString(), null, null, true, null);
    }
    
    // Session-specific audit log methods
    public Mono<AuditLog> logSessionCreation(String userId, String sessionId, String ipAddress) {
        Long userIdLong = parseUserId(userId);
        return log(userIdLong, "SESSION_CREATE", "SESSION", sessionId,
                null, null, ipAddress, null, true, null);
    }
    
    public Mono<AuditLog> logSessionIpChange(String userId, String sessionId, String oldIp, String newIp) {
        Long userIdLong = parseUserId(userId);
        return log(userIdLong, "SESSION_IP_CHANGE", "SESSION", sessionId,
                oldIp, newIp, null, null, true, "IP address changed from " + oldIp + " to " + newIp);
    }
    
    public Mono<AuditLog> logSessionLogout(String userId, String sessionId, String reason) {
        Long userIdLong = parseUserId(userId);
        return log(userIdLong, "SESSION_LOGOUT", "SESSION", sessionId,
                null, null, null, null, true, reason);
    }
    
    public Mono<AuditLog> logSessionTermination(String terminatedBy, String userId, String sessionId, String reason) {
        Long terminatedById = parseUserId(terminatedBy);
        Long userIdLong = parseUserId(userId);
        
        // Use the userIdLong for logging, but keep String userId in the message for context
        String logMessage = "Session terminated. User: " + (userIdLong != null ? userIdLong.toString() : userId) + ", Reason: " + reason;
        
        return log(terminatedById, "SESSION_TERMINATE", "SESSION", sessionId,
                null, null, null, null, true, logMessage);
    }
    
    // Query methods - need to handle both String and Long
    public Flux<AuditLog> getAuditLogsByUserId(String userIdStr, int page, int size) {
        Long userId = parseUserId(userIdStr);
        if (userId == null) {
            return Flux.error(new IllegalArgumentException("Invalid user ID: " + userIdStr));
        }
        
        return auditLogRepository.findByUserId(userId,
                org.springframework.data.domain.PageRequest.of(page, size,
                        org.springframework.data.domain.Sort.by("timestamp").descending()));
    }
    
    public Flux<AuditLog> getAuditLogsByAction(String action, int page, int size) {
        return auditLogRepository.findByAction(action,
                org.springframework.data.domain.PageRequest.of(page, size,
                        org.springframework.data.domain.Sort.by("timestamp").descending()));
    }
    
    public Flux<AuditLog> getAuditLogsByDateRange(LocalDateTime startDate, LocalDateTime endDate, int page, int size) {
        return auditLogRepository.findByTimestampBetween(startDate, endDate,
                org.springframework.data.domain.PageRequest.of(page, size,
                        org.springframework.data.domain.Sort.by("timestamp").descending()));
    }
    
    // Helper method to parse userId
    private Long parseUserId(String userIdStr) {
        if (userIdStr == null) {
            return null;
        }
        try {
            return Long.parseLong(userIdStr);
        } catch (NumberFormatException e) {
            log.warn("Invalid user ID format: {}", userIdStr);
            return null; // For non-numeric IDs like "SYSTEM"
        }
    }
}