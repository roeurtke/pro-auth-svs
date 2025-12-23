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
    
    public Mono<AuditLog> log(String userId, String action, String resourceType, 
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
        
        return auditLogRepository.save(auditLog);
    }
    
    public Mono<AuditLog> logLoginSuccess(String username, String ipAddress, String userAgent) {
        return log(username, "LOGIN_SUCCESS", "USER", null, null, null,
                ipAddress, userAgent, true, null);
    }
    
    public Mono<AuditLog> logLoginFailure(String username, String ipAddress, String userAgent, String error) {
        return log(username, "LOGIN_FAILURE", "USER", null, null, null,
                ipAddress, userAgent, false, error);
    }
    
    public Mono<AuditLog> logLogout(String userId, String ipAddress) {
        return log(userId, "LOGOUT", "USER", null, null, null,
                ipAddress, null, true, null);
    }
    
    public Mono<AuditLog> logRegistration(String username) {
        return log(username, "REGISTRATION", "USER", null, null, null,
                null, null, true, null);
    }
    
    public Mono<AuditLog> logPasswordChange(Long userId) {
        return log(userId.toString(), "PASSWORD_CHANGE", "USER", userId.toString(),
                null, null, null, null, true, null);
    }
    
    public Mono<AuditLog> logUserUpdate(Long userId, String description) {
        return log(userId.toString(), "USER_UPDATE", "USER", userId.toString(),
                null, description, null, null, true, null);
    }
    
    public Mono<AuditLog> logUserEnable(Long userId) {
        return log(userId.toString(), "USER_ENABLE", "USER", userId.toString(),
                "DISABLED", "ENABLED", null, null, true, null);
    }
    
    public Mono<AuditLog> logUserDisable(Long userId) {
        return log(userId.toString(), "USER_DISABLE", "USER", userId.toString(),
                "ENABLED", "DISABLED", null, null, true, null);
    }
    
    public Mono<AuditLog> logUserLock(Long userId) {
        return log(userId.toString(), "USER_LOCK", "USER", userId.toString(),
                "UNLOCKED", "LOCKED", null, null, true, null);
    }
    
    public Mono<AuditLog> logUserUnlock(Long userId) {
        return log(userId.toString(), "USER_UNLOCK", "USER", userId.toString(),
                "LOCKED", "UNLOCKED", null, null, true, null);
    }
    
    public Mono<AuditLog> logRoleCreation(Long roleId, String roleName) {
        return log("SYSTEM", "ROLE_CREATE", "ROLE", roleId.toString(),
                null, roleName, null, null, true, null);
    }
    
    public Mono<AuditLog> logRoleUpdate(Long roleId, String description) {
        return log("SYSTEM", "ROLE_UPDATE", "ROLE", roleId.toString(),
                null, description, null, null, true, null);
    }
    
    public Mono<AuditLog> logRoleDeletion(Long roleId, String roleName) {
        return log("SYSTEM", "ROLE_DELETE", "ROLE", roleId.toString(),
                roleName, null, null, null, true, null);
    }
    
    public Mono<AuditLog> logRoleAssignment(Long userId, Long roleId) {
        return log("SYSTEM", "ROLE_ASSIGN", "USER_ROLE", userId + ":" + roleId,
                null, "ASSIGNED", null, null, true, null);
    }
    
    public Mono<AuditLog> logRoleRemoval(Long userId, Long roleId) {
        return log("SYSTEM", "ROLE_REMOVE", "USER_ROLE", userId + ":" + roleId,
                "ASSIGNED", null, null, null, true, null);
    }
    
    public Mono<AuditLog> logPermissionCreation(Long permissionId, String permissionName) {
        return log("SYSTEM", "PERMISSION_CREATE", "PERMISSION", permissionId.toString(),
                null, permissionName, null, null, true, null);
    }
    
    public Mono<AuditLog> logPermissionUpdate(Long permissionId, String description) {
        return log("SYSTEM", "PERMISSION_UPDATE", "PERMISSION", permissionId.toString(),
                null, description, null, null, true, null);
    }
    
    public Mono<AuditLog> logPermissionDeletion(Long permissionId, String permissionName) {
        return log("SYSTEM", "PERMISSION_DELETE", "PERMISSION", permissionId.toString(),
                permissionName, null, null, null, true, null);
    }
    
    public Mono<AuditLog> logPermissionsAssignment(Long roleId, Set<Long> permissionIds) {
        return log("SYSTEM", "PERMISSIONS_ASSIGN", "ROLE_PERMISSION", roleId.toString(),
                null, permissionIds.toString(), null, null, true, null);
    }
    
    // Session-specific audit log methods
    
    public Mono<AuditLog> logSessionCreation(String userId, String sessionId, String ipAddress) {
        return log(userId, "SESSION_CREATE", "SESSION", sessionId,
                null, null, ipAddress, null, true, null);
    }
    
    public Mono<AuditLog> logSessionIpChange(String userId, String sessionId, String oldIp, String newIp) {
        return log(userId, "SESSION_IP_CHANGE", "SESSION", sessionId,
                oldIp, newIp, null, null, true, "IP address changed from " + oldIp + " to " + newIp);
    }
    
    public Mono<AuditLog> logSessionLogout(String userId, String sessionId, String reason) {
        return log(userId, "SESSION_LOGOUT", "SESSION", sessionId,
                null, null, null, null, true, reason);
    }
    
    public Mono<AuditLog> logSessionTermination(String terminatedBy, String userId, String sessionId, String reason) {
        return log(terminatedBy, "SESSION_TERMINATE", "SESSION", sessionId,
                null, null, null, null, true, "Session terminated. User: " + userId + ", Reason: " + reason);
    }
    
    // Query methods
    
    public Flux<AuditLog> getAuditLogsByUserId(String userId, int page, int size) {
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
}