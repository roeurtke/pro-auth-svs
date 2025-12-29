package com.core.auth.service;

import com.core.auth.dto.request.AuthRequest;
import com.core.auth.dto.request.RegisterRequest;
import com.core.auth.dto.response.AuthResponse;
import com.core.auth.exception.AuthException;
import com.core.auth.model.User;
import com.core.auth.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashSet;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    
    private final UserService userService;
    private final RoleService roleService;
    private final TokenService tokenService;
    private final SessionService sessionService;
    private final AuditLogService auditLogService;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final CustomUserDetailsService userDetailsService;
    
    @Qualifier("loginAuthenticationManager")
    private final ReactiveAuthenticationManager loginAuthenticationManager;
    
    @Transactional
    public Mono<User> incrementFailedLogin(User user) {
        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
        if (user.getFailedLoginAttempts() >= 5) {
            user.setLocked(true);
        }
        return userService.save(user);
    }

    public Mono<AuthResponse> login(AuthRequest request, String ipAddress, String userAgent) {
        log.info("LOGIN ATTEMPT - Username: {}, IP: {}", request.getUsername(), ipAddress);
        
        return userService.findByUsername(request.getUsername())
            .switchIfEmpty(Mono.defer(() -> {
                log.warn("USER NOT FOUND - Username: {}", request.getUsername());
                return Mono.error(new AuthException("User not found"));
            }))
            .doOnNext(user -> {
                log.info("USER FOUND - Username: {}, Enabled: {}, Locked: {}, Password in DB: {}", 
                    user.getUsername(), user.isEnabled(), user.isLocked(),
                    user.getPassword() != null ? "[HASHED]" : "NULL");
            })
            .flatMap(user -> {
                if (!user.isEnabled()) {
                    log.warn("ACCOUNT DISABLED - Username: {}", user.getUsername());
                    return Mono.error(new AuthException("Account is disabled"));
                }
                if (user.isLocked()) {
                    log.warn("ACCOUNT LOCKED - Username: {}", user.getUsername());
                    return Mono.error(new AuthException("Account is locked"));
                }

                // Use manual authentication since AuthenticationManager has bean issues
                return manualAuthentication(user, request, ipAddress, userAgent);
            });
    }
    
    private Mono<AuthResponse> manualAuthentication(User user, AuthRequest request, String ipAddress, String userAgent) {
        log.info("Using manual authentication for: {}", user.getUsername());
        
        return userDetailsService.findByUsername(request.getUsername())
            .flatMap(userDetails -> {
                // Check password manually
                if (!passwordEncoder.matches(request.getPassword(), userDetails.getPassword())) {
                    log.warn("Password mismatch for user: {}", user.getUsername());
                    return processFailedLogin(user, ipAddress, userAgent);
                }
                
                log.info("Password verified successfully for user: {}", user.getUsername());
                
                // Get authorities - handle as synchronous call
                return Mono.fromCallable(() -> roleService.getAuthoritiesForUser(user.getId()))
                    .onErrorResume(e -> {
                        log.warn("Failed to get authorities, using empty set: {}", e.getMessage());
                        return Mono.just(new HashSet<GrantedAuthority>());
                    })
                    .flatMap(authorities -> {
                        Authentication auth = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            authorities
                        );
                        log.info("Created authentication with {} authorities", authorities.size());
                        return processSuccessfulLogin(user, request, auth, ipAddress, userAgent);
                    });
            })
            .onErrorResume(e -> {
                log.error("Authentication error: {}", e.getMessage());
                return Mono.error(new AuthException("Invalid username or password"));
            });
    }

    private Mono<AuthResponse> processSuccessfulLogin(User user, AuthRequest request, Authentication auth, String ipAddress, String userAgent) {
        // Reset failed attempts and update last login
        user.setFailedLoginAttempts(0);
        user.setLastLoginAt(LocalDateTime.now());

        return userService.save(user)
            .flatMap(savedUser -> {
                // MFA check
                if (savedUser.isMfaEnabled()) {
                    if (request.getMfaCode() == null || request.getMfaCode().isEmpty()) {
                        return Mono.just(AuthResponse.builder()
                            .mfaRequired(true)
                            .user(userService.mapToResponse(savedUser))
                            .build());
                    }

                    return verifyMfa(savedUser, request.getMfaCode())
                        .flatMap(valid -> {
                            if (!valid) {
                                return Mono.error(new AuthException("Invalid MFA code"));
                            }
                            return generateTokens(savedUser, auth, ipAddress, userAgent);
                        });
                }

                return generateTokens(savedUser, auth, ipAddress, userAgent);
            })
            .doOnSuccess(resp -> auditLogService.logLoginSuccess(user.getUsername(), ipAddress, userAgent))
            .doOnError(err -> auditLogService.logLoginFailure(user.getUsername(), ipAddress, userAgent, err.getMessage()));
    }

    private Mono<AuthResponse> processFailedLogin(User user, String ipAddress, String userAgent) {
        return incrementFailedLogin(user)
            .doOnSuccess(savedUser -> auditLogService.logLoginFailure(
                user.getUsername(), ipAddress, userAgent, "Invalid username or password"))
            .then(Mono.error(new AuthException("Invalid username or password")));
    }
    
    @Transactional
    public Mono<AuthResponse> register(RegisterRequest request) {
        return userService.existsByUsername(request.getUsername())
            .flatMap(exists -> {
                if (exists) {
                    return Mono.error(new AuthException("Username already exists"));
                }
                return userService.existsByEmail(request.getEmail());
            })
            .flatMap(exists -> {
                if (exists) {
                    return Mono.error(new AuthException("Email already exists"));
                }

                User user = User.builder()
                    .username(request.getUsername())
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .firstName(request.getFirstName())
                    .lastName(request.getLastName())
                    .phone(request.getPhone())
                    .enabled(true)
                    .locked(false)
                    .mfaEnabled(false)
                    .createdAt(LocalDateTime.now())
                    .updatedAt(LocalDateTime.now())
                    .build();

                return userService.save(user)
                    .flatMap(savedUser ->
                        roleService.assignDefaultRole(savedUser.getId())
                            .thenReturn(savedUser)
                    )
                    .map(savedUser ->
                        AuthResponse.builder()
                            .user(userService.mapToResponse(savedUser))
                            .build()
                    );
            })
            .doOnSuccess(response ->
                auditLogService.logRegistration(response.getUser().getUsername())
            );
    }
    
    @Transactional
    public Mono<AuthResponse> refreshToken(String refreshToken, String ipAddress, String userAgent) {
        return tokenService.validateRefreshToken(refreshToken)
            .flatMap(token -> {
                String username = jwtTokenProvider.getUsernameFromToken(refreshToken);
                
                return userService.findByUsername(username)
                        .flatMap(user -> {
                            // Create new authentication
                            Authentication auth = new UsernamePasswordAuthenticationToken(
                                    user.getUsername(),
                                    null,
                                    roleService.getAuthoritiesForUser(user.getId())
                            );
                            
                            // Generate new tokens
                            return generateTokens(user, auth, ipAddress, userAgent);
                        });
            });
    }
    
    @Transactional
    public Mono<Void> logout(String token, String userId, String ipAddress) {
        return tokenService.revokeToken(token)
            .then(sessionService.logout(userId, ipAddress))
            .doOnSuccess(v -> 
                auditLogService.logLogout(userId, ipAddress)
            );
    }
    
    private Mono<AuthResponse> generateTokens(User user, Authentication auth, String ipAddress, String userAgent) {
        log.info("=== Testing Token/Session Saving ===");
        
        return Mono.zip(
                    generateAccessToken(user, auth.getAuthorities()),
                    generateRefreshToken(user)
            )
            .flatMap(tuple -> {
                String accessToken = tuple.getT1();
                String refreshToken = tuple.getT2();
                
                log.info("1. Testing Token Save...");
                return tokenService.saveRefreshToken(user.getId().toString(), refreshToken)
                        .doOnSuccess(v -> log.info("   ✅ Token saved successfully"))
                        .doOnError(e -> {
                            log.error("   ❌ Token save failed: {}", e.getMessage());
                            log.error("   Stack trace:", e);
                        })
                        .onErrorResume(e -> {
                            log.warn("   ⚠️ Continuing without token save");
                            return Mono.empty(); // Continue even if token save fails
                        })
                        .then(Mono.defer(() -> {
                            log.info("2. Testing Session Creation...");
                            return sessionService.createSession(user.getId().toString(), ipAddress, userAgent)
                                    .doOnSuccess(s -> log.info("   ✅ Session created: ID={}", s.getId()))
                                    .doOnError(e -> {
                                        log.error("   ❌ Session creation failed: {}", e.getMessage());
                                        log.error("   Stack trace:", e);
                                    })
                                    .onErrorResume(e -> {
                                        log.warn("   ⚠️ Continuing without session");
                                        return Mono.empty(); // Continue even if session fails
                                    })
                                    .thenReturn(AuthResponse.builder()
                                            .accessToken(accessToken)
                                            .refreshToken(refreshToken)
                                            .expiresIn(jwtTokenProvider.getExpirationDateFromToken(accessToken)
                                                    .atZone(java.time.ZoneId.systemDefault())
                                                    .toInstant()
                                                    .toEpochMilli())
                                            .tokenType("Bearer")
                                            // .user(userService.mapToResponse(user))
                                            .mfaRequired(false)
                                            .build());
                        }));
            })
            .doOnNext(response -> log.info("=== AuthResponse created successfully ==="))
            .doOnError(e -> log.error("=== Error in generateTokens: {} ===", e.getMessage()));
    }
    
    private Mono<String> generateAccessToken(User user, java.util.Collection<? extends org.springframework.security.core.GrantedAuthority> authorities) {
        return Mono.just(jwtTokenProvider.generateAccessToken(user, authorities));
    }
    
    private Mono<String> generateRefreshToken(User user) {
        return Mono.just(jwtTokenProvider.generateRefreshToken(user));
    }
    
    // ADDED THIS METHOD:
    private Mono<Boolean> verifyMfa(User user, String code) {
        // Implement MFA verification
        // This is a placeholder - implement actual TOTP verification
        return Mono.just(true);
    }
}