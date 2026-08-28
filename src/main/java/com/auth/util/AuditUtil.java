package com.auth.util;

import com.auth.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import reactor.core.publisher.Mono;

/**
 * @author Roeurt Kesei
 * Utility class for security-related operations
 */
public class AuditUtil {
    
    private AuditUtil() {
        // Private constructor to prevent instantiation
        throw new UnsupportedOperationException("Utility class should not be instantiated");
    }
    
    /**
     * Get the current authenticated user's ID
     * @return Mono containing the user ID or Mono.empty() if not authenticated
     */
    public static Mono<Long> getCurrentUserId() {
        return ReactiveSecurityContextHolder.getContext()
            .map(SecurityContext::getAuthentication)
            .flatMap(AuditUtil::extractUserIdFromAuthentication);
    }
    
    /**
     * Get the current authenticated user object
     * @return Mono containing the User or Mono.empty() if not authenticated
     */
    public static Mono<User> getCurrentUser() {
        return ReactiveSecurityContextHolder.getContext()
            .map(SecurityContext::getAuthentication)
            .flatMap(AuditUtil::extractUserFromAuthentication);
    }
    
    /**
     * Get the current authenticated user's username
     * @return Mono containing the username or Mono.empty() if not authenticated
     */
    public static Mono<String> getCurrentUsername() {
        return ReactiveSecurityContextHolder.getContext()
            .map(SecurityContext::getAuthentication)
            .flatMap(authentication -> {
                if (authentication != null && authentication.isAuthenticated()) {
                    return Mono.just(authentication.getName());
                }
                return Mono.empty();
            });
    }
    
    /**
     * Check if current user has a specific role
     * @param roleName the role name (without ROLE_ prefix)
     * @return Mono containing boolean indicating if user has the role
     */
    public static Mono<Boolean> hasRole(String roleName) {
        return ReactiveSecurityContextHolder.getContext()
            .map(SecurityContext::getAuthentication)
            .flatMap(authentication -> {
                if (authentication != null) {
                    return authentication.getAuthorities().stream()
                        .anyMatch(grantedAuthority -> 
                            grantedAuthority.getAuthority().equals("ROLE_" + roleName))
                        ? Mono.just(true) : Mono.just(false);
                }
                return Mono.just(false);
            });
    }
    
    /**
     * Check if current user has a specific permission
     * @param permissionName the permission name
     * @return Mono containing boolean indicating if user has the permission
     */
    public static Mono<Boolean> hasPermission(String permissionName) {
        return ReactiveSecurityContextHolder.getContext()
            .map(SecurityContext::getAuthentication)
            .flatMap(authentication -> {
                if (authentication != null) {
                    return authentication.getAuthorities().stream()
                        .anyMatch(grantedAuthority -> 
                            grantedAuthority.getAuthority().equals(permissionName))
                        ? Mono.just(true) : Mono.just(false);
                }
                return Mono.just(false);
            });
    }
    
    /**
     * Check if user is authenticated
     * @return Mono containing boolean indicating if user is authenticated
     */
    public static Mono<Boolean> isAuthenticated() {
        return ReactiveSecurityContextHolder.getContext()
            .map(SecurityContext::getAuthentication)
            .flatMap(authentication -> 
                Mono.just(authentication != null && authentication.isAuthenticated())
            );
    }
    
    /**
     * Extract user ID from authentication object
     */
    private static Mono<Long> extractUserIdFromAuthentication(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof User) {
            User user = (User) authentication.getPrincipal();
            return Mono.just(user.getId());
        }
        return Mono.empty();
    }
    
    /**
     * Extract user object from authentication object
     */
    private static Mono<User> extractUserFromAuthentication(Authentication authentication) {
        if (authentication != null && authentication.getPrincipal() instanceof User) {
            return Mono.just((User) authentication.getPrincipal());
        }
        return Mono.empty();
    }
    
    /**
     * Get current user ID or throw exception if not authenticated
     * Useful for methods that require authentication
     */
    public static Mono<Long> getCurrentUserIdOrThrow() {
        return getCurrentUserId()
            .switchIfEmpty(Mono.error(new RuntimeException("User not authenticated")));
    }
    
    /**
     * Get current user or throw exception if not authenticated
     */
    public static Mono<User> getCurrentUserOrThrow() {
        return getCurrentUser()
            .switchIfEmpty(Mono.error(new RuntimeException("User not authenticated")));
    }
}