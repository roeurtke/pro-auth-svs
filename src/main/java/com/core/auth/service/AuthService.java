package com.core.auth.service;

import com.core.auth.dto.request.AuthRequest;
import com.core.auth.dto.request.RegisterRequest;
import com.core.auth.dto.response.AuthResponse;
import com.core.auth.exception.AuthException;
import com.core.auth.model.User;
import com.core.auth.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

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
    private final ReactiveAuthenticationManager loginAuthenticationManager;
    
    @Transactional
    public Mono<AuthResponse> login(AuthRequest request, String ipAddress, String userAgent) {
        return userService.findByUsernameOrEmail(request.getUsername())
                .switchIfEmpty(Mono.error(new AuthException("User not found")))
                .flatMap(user -> {
                    if (!user.isEnabled()) {
                        return Mono.error(new AuthException("Account is disabled"));
                    }
                    if (user.isLocked()) {
                        return Mono.error(new AuthException("Account is locked"));
                    }

                    // Authenticate password reactively
                    return loginAuthenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                        )
                    )
                    .flatMap(auth -> handleSuccessfulLogin(user, auth, request, ipAddress, userAgent))
                    .onErrorResume(e -> handleAuthenticationError(e, request, ipAddress, userAgent));
                })
                .onErrorResume(e -> handleFailedLogin(request.getUsername(), e, ipAddress, userAgent));
    }

    private Mono<AuthResponse> handleSuccessfulLogin(User user,
                                                    Authentication auth,
                                                    AuthRequest request,
                                                    String ipAddress,
                                                    String userAgent) {

        // Reset failed attempts
        user.setFailedLoginAttempts(0);
        user.setLastLoginAt(LocalDateTime.now());

        return userService.save(user)
                .flatMap(savedUser -> {
                    // Handle MFA
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
    
    private Mono<AuthResponse> handleFailedLogin(String username, Throwable e, String ipAddress, String userAgent) {
        return userService.findByUsernameOrEmail(username)
                .flatMap(user -> {
                    user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
                    if (user.getFailedLoginAttempts() >= 5) {
                        user.setLocked(true);
                    }
                    return userService.save(user);
                })
                .onErrorResume(err -> Mono.empty()) // ignore errors while updating user
                .then(Mono.<AuthResponse>error(e))  // explicitly tell compiler the type
                .doOnError(err -> auditLogService.logLoginFailure(username, ipAddress, userAgent, err.getMessage()));
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
                    
                    // Create user
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
                            .flatMap(savedUser -> {
                                // Assign default role (USER)
                                return roleService.assignDefaultRole(savedUser.getId())
                                        .thenReturn(savedUser);
                            })
                            .map(savedUser -> {
                                // Return response without tokens (user needs to login)
                                return AuthResponse.builder()
                                        .user(userService.mapToResponse(user))
                                        .build();
                            });
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
    
    private Mono<Boolean> verifyMfa(User user, String code) {
        // Implement MFA verification
        // This is a placeholder - implement actual TOTP verification
        return Mono.just(true);
    }
    
    private Mono<AuthResponse> generateTokens(User user, Authentication auth, String ipAddress, String userAgent) {
        return Mono.zip(
                        generateAccessToken(user, auth.getAuthorities()),
                        generateRefreshToken(user)
                )
                .flatMap(tuple -> {
                    String accessToken = tuple.getT1();
                    String refreshToken = tuple.getT2();

                    // Save refresh token and create session reactively
                    return tokenService.saveRefreshToken(user.getId().toString(), refreshToken)
                            .then(sessionService.createSession(user.getId().toString(), ipAddress, userAgent))
                            .map(session -> AuthResponse.builder()
                                    .accessToken(accessToken)
                                    .refreshToken(refreshToken)
                                    .expiresIn(jwtTokenProvider.getExpirationDateFromToken(accessToken)
                                            .atZone(java.time.ZoneId.systemDefault())
                                            .toInstant()
                                            .toEpochMilli())
                                    .tokenType("Bearer")
                                    .user(userService.mapToResponse(user))
                                    .mfaRequired(false)
                                    .build());
                });
    }
    
    private Mono<String> generateAccessToken(User user, java.util.Collection<? extends org.springframework.security.core.GrantedAuthority> authorities) {
        return Mono.just(jwtTokenProvider.generateAccessToken(user, authorities));
    }
    
    private Mono<String> generateRefreshToken(User user) {
        return Mono.just(jwtTokenProvider.generateRefreshToken(user));
    }

    private Mono<AuthResponse> handleAuthenticationError(
            Throwable e,
            AuthRequest request,
            String ipAddress,
            String userAgent) {

        if (e instanceof BadCredentialsException) {
            return handleFailedLogin(
                    request.getUsername(),
                    new AuthException("Invalid username or password"),
                    ipAddress,
                    userAgent
            );
        }

        log.error("Unexpected authentication error", e);
        return Mono.error(new AuthException("Authentication failed"));
    }
}