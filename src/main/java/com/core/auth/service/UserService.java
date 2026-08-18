package com.core.auth.service;

import com.core.auth.dto.request.UserCreateRequest;
import com.core.auth.dto.request.UserUpdateRequest;
import com.core.auth.dto.response.UserResponse;
import com.core.auth.exception.UserNotFoundException;
import com.core.auth.model.User;
import com.core.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    
    private final UserRepository userRepository;
    private final RoleService roleService;
    private final PasswordEncoder passwordEncoder;
    private final AuditLogService auditLogService;
    
    public Mono<User> findById(Long id) {
        return userRepository.findById(id)
                .switchIfEmpty(Mono.error(new UserNotFoundException(id)));
    }
    
    public Mono<User> findByUsername(String username) {
        return userRepository.findByUsername(username)
                .switchIfEmpty(Mono.error(new UserNotFoundException(username)));
    }
    
    public Mono<User> findByUsernameOrEmail(String identifier) {
        return userRepository.findByUsernameOrEmail(identifier, identifier)
                .switchIfEmpty(Mono.error(new UserNotFoundException(identifier)));
    }
    
    public Mono<User> findByEmail(String email) {
        return userRepository.findByEmail(email)
                .switchIfEmpty(Mono.error(new UserNotFoundException(email)));
    }
    
    public Flux<User> findAll() {
        return userRepository.findAll();
    }
    
    public Mono<Boolean> existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }
    
    public Mono<Boolean> existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }
    
    @Transactional
    public Mono<User> save(User user) {
        if (user.getId() == null) {
            user.setCreatedAt(LocalDateTime.now());
        }
        user.setUpdatedAt(LocalDateTime.now());
        return userRepository.save(user);
    }

    @Transactional
    public Mono<User> createUser(UserCreateRequest request) {
        return userRepository.existsByUsername(request.getUsername())
                .flatMap(usernameExists -> {
                    if (usernameExists) {
                        return Mono.error(new RuntimeException("Username already exists"));
                    }
                    return userRepository.existsByEmail(request.getEmail());
                })
                .flatMap(emailExists -> {
                    if (emailExists) {
                        return Mono.error(new RuntimeException("Email already exists"));
                    }

                    User user = User.builder()
                            .username(request.getUsername())
                            .email(request.getEmail())
                            .password(passwordEncoder.encode(request.getPassword()))
                            .firstName(request.getFirstName())
                            .lastName(request.getLastName())
                            .phone(request.getPhone())
                            .enabled(request.getEnabled() == null || request.getEnabled())
                            .locked(false)
                            .mfaEnabled(false)
                            .failedLoginAttempts(0)
                            .createdAt(LocalDateTime.now())
                            .updatedAt(LocalDateTime.now())
                            .build();

                    return userRepository.save(user);
                })
                .flatMap(savedUser -> {
                    // If roleIds were supplied by the admin, assign those roles.
                    // Otherwise assign the default USER role.
                    if (request.getRoleIds() != null && !request.getRoleIds().isEmpty()) {
                        return roleService.updateUserRoles(savedUser.getId(), request.getRoleIds())
                                .thenReturn(savedUser);
                    }
                    return roleService.assignDefaultRole(savedUser.getId())
                            .thenReturn(savedUser);
                })
                .doOnSuccess(savedUser ->
                        auditLogService.logUserUpdate(savedUser.getId(), "User account created"));
    }    

    @Transactional
    public Mono<User> updateProfile(Long userId, UserUpdateRequest request) {
        return findById(userId)
                .flatMap(user -> {
                    if (request.getFirstName() != null) {
                        user.setFirstName(request.getFirstName());
                    }
                    if (request.getLastName() != null) {
                        user.setLastName(request.getLastName());
                    }
                    if (request.getEmail() != null) {
                        user.setEmail(request.getEmail());
                    }
                    if (request.getPhone() != null) {
                        user.setPhone(request.getPhone());
                    }
                    
                    return save(user)
                            .doOnSuccess(updatedUser -> 
                                auditLogService.logUserUpdate(userId, "User profile updated")
                            );
                });
    }

    @Transactional
    public Mono<User> updateUser(Long userId, UserUpdateRequest request) {
        return findById(userId)
                .flatMap(user -> {
                    if (request.getUsername() != null) {
                        user.setUsername(request.getUsername());
                    }
                    if (request.getFirstName() != null) {
                        user.setFirstName(request.getFirstName());
                    }
                    if (request.getLastName() != null) {
                        user.setLastName(request.getLastName());
                    }
                    if (request.getEmail() != null) {
                        user.setEmail(request.getEmail());
                    }
                    if (request.getPhone() != null) {
                        user.setPhone(request.getPhone());
                    }
                    if (request.getEnabled() != null) {
                        user.setEnabled(request.getEnabled());
                    }
                    if (request.getLocked() != null) {
                        user.setLocked(request.getLocked());
                    }
                    if (request.getMfaEnabled() != null) {
                        user.setMfaEnabled(request.getMfaEnabled());
                    }
                    if (request.getMfaSecret() != null) {
                        user.setMfaSecret(request.getMfaSecret());
                    }

                    return save(user)
                            .flatMap(updatedUser -> {

                                if (request.getRoleIds() != null) {
                                    return roleService
                                            .updateUserRoles(userId,request.getRoleIds())
                                            .thenReturn(updatedUser);
                                }

                                return Mono.just(updatedUser);
                            })
                            .doOnSuccess(updatedUser ->
                                    auditLogService.logUserUpdate(
                                            userId,
                                            "User account updated by administrator"
                                    )
                            );
                });
    }

    @Transactional
    public Mono<Void> deleteUser(Long userId) {
        return findById(userId)
                .flatMap(user -> userRepository.delete(user)
                        .doOnSuccess(v -> auditLogService.logUserDeletion(userId)));
    }

    @Transactional
    public Mono<Void> changePassword(Long userId, String oldPassword, String newPassword) {
        return findById(userId)
                .flatMap(user -> {
                    if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
                        return Mono.error(new RuntimeException("Current password is incorrect"));
                    }
                    
                    user.setPassword(passwordEncoder.encode(newPassword));
                    user.setPasswordChangedAt(LocalDateTime.now());
                    
                    return save(user)
                            .doOnSuccess(updatedUser -> 
                                auditLogService.logPasswordChange(userId)
                            )
                            .then();
                });
    }
    
    @Transactional
    public Mono<Void> enableUser(Long userId) {
        return findById(userId)
                .flatMap(user -> {
                    user.setEnabled(true);
                    return save(user)
                            .doOnSuccess(updatedUser -> 
                                auditLogService.logUserEnable(userId)
                            )
                            .then();
                });
    }
    
    @Transactional
    public Mono<Void> disableUser(Long userId) {
        return findById(userId)
                .flatMap(user -> {
                    user.setEnabled(false);
                    return save(user)
                            .doOnSuccess(updatedUser -> 
                                auditLogService.logUserDisable(userId)
                            )
                            .then();
                });
    }
    
    @Transactional
    public Mono<Void> lockUser(Long userId) {
        return findById(userId)
                .flatMap(user -> {
                    user.setLocked(true);
                    return save(user)
                            .doOnSuccess(updatedUser -> 
                                auditLogService.logUserLock(userId)
                            )
                            .then();
                });
    }
    
    @Transactional
    public Mono<Void> unlockUser(Long userId) {
        return findById(userId)
                .flatMap(user -> {
                    user.setLocked(false);
                    user.setFailedLoginAttempts(0);
                    return save(user)
                            .doOnSuccess(updatedUser -> 
                                auditLogService.logUserUnlock(userId)
                            )
                            .then();
                });
    }
    
    @Transactional
    public Mono<UserResponse> getUserWithDetails(Long userId) {
        return findById(userId)
                .flatMap(user ->
                    roleService.getUserWithAuthorities(userId)
                            .map(userWithAuthorities -> {
                                user.setRoles(userWithAuthorities.getRoles());
                                return mapToResponse(user);
                            })
                );
    }
    
    public UserResponse mapToResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .phone(user.getPhone())
                .enabled(user.isEnabled())
                .mfaEnabled(user.isMfaEnabled())
                .createdAt(user.getCreatedAt())
                .lastLoginAt(user.getLastLoginAt())
                .roles(roleService.mapRolesToResponse(user.getRoles()))
                .build();
    }

}