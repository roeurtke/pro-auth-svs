package com.auth.service;

import com.auth.dto.request.UserCreateRequest;
import com.auth.dto.response.PageResponse;
import com.auth.dto.response.UserResponse;
import com.auth.exception.DeletedExceptionHandler;
import com.auth.model.Permission;
import com.auth.model.Role;
import com.auth.model.RolePermission;
import com.auth.model.User;
import com.auth.model.UserRole;
import com.auth.repository.UserRepository;
import com.auth.repository.UserRoleRepository;
import com.auth.repository.RoleRepository;
import com.auth.repository.RolePermissionRepository;
import com.auth.repository.PermissionRepository;
import com.auth.util.EnumStatus;
import com.auth.util.AuditUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * @author Roeurt Kesei
 * Service for managing users.
 */
@Service
public class UserService implements ReactiveUserDetailsService {
    
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final RoleRepository roleRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final PermissionRepository permissionRepository;
    private final PasswordEncoder passwordEncoder;
    
    public UserService(
        UserRepository userRepository,
        UserRoleRepository userRoleRepository,
        RoleRepository roleRepository,
        RolePermissionRepository rolePermissionRepository,
        PermissionRepository permissionRepository,
        PasswordEncoder passwordEncoder
    ) {
        this.userRepository = userRepository;
        this.userRoleRepository = userRoleRepository;
        this.roleRepository = roleRepository;
        this.rolePermissionRepository = rolePermissionRepository;
        this.permissionRepository = permissionRepository;
        this.passwordEncoder = passwordEncoder;
    }
    
    @Override
    @Transactional
    public Mono<UserDetails> findByUsername(String username) {
        return userRepository.findByUsernameAndIsDeletedFalse(username)
            .switchIfEmpty(Mono.error(new UsernameNotFoundException("User not found: " + username)))
            .flatMap(user -> loadUserRoles(user)
                .thenReturn(user)
                .cast(UserDetails.class)
            );
    }
    
    public Mono<PageResponse<UserResponse>> findAllUsers(int page, int size) {
        long offset = (long) page * size;

        Mono<List<UserResponse>> users = userRepository.findAllByIsDeletedFalse(size, offset)
            .concatMap(user -> loadUserRoles(user).thenReturn(user))
            .flatMap(this::mapUserToDto)
            .collectList();

        return Mono.zip(userRepository.countByIsDeletedFalse(), users)
            .map(result -> new PageResponse<>(
                result.getT2(),
                page,
                size,
                result.getT1()
            ));
    }
    
    public Mono<UserResponse> findUserById(Long id) {
        return userRepository.findById(id)
                .switchIfEmpty(Mono.error(new RuntimeException("User not found with id: " + id)))
                .flatMap(user -> {
                    if (Boolean.TRUE.equals(user.getIsDeleted())) {
                        return Mono.error(new DeletedExceptionHandler(id));
                    }
                    return loadUserRoles(user).thenReturn(user);
                })
                .flatMap(this::mapUserToDto);
    }

    /**
     * Check if a user exists by username.
     * @param username The username to check.
     * @return A Mono emitting true if the user exists, false otherwise.
     */
    public Mono<Boolean> existsByUsername(String username) {
        return userRepository.existsByUsernameAndIsDeletedFalse(username);
    }
    
    /**
     * Check if a user exists by email.
     * @param email The email to check.
     * @return A Mono emitting true if the user exists, false otherwise.
     */
    public Mono<Boolean> existsByEmail(String email) {
        return userRepository.existsByEmailAndIsDeletedFalse(email);
    }

    private Mono<Void> ensureUniqueUserCredentials(String username, String email) {
        return existsByUsername(username)
            .flatMap(exists -> exists
                ? Mono.error(new RuntimeException("Username already exists"))
                : Mono.empty())
            .then(existsByEmail(email))
            .flatMap(exists -> exists
                ? Mono.error(new RuntimeException("Email already exists"))
                : Mono.empty());
    }

    private Mono<User> assignUserRoles(User user, java.util.Collection<Long> roleIds) {
        return Mono.defer(() -> {
            java.util.Collection<Long> resolvedRoleIds;

            if (roleIds == null || roleIds.isEmpty()) {
                return roleRepository.findByName("USER")
                    .switchIfEmpty(Mono.error(new RuntimeException("Default USER role not found")))
                    .map(role -> java.util.Collections.singletonList(role.getId()))
                    .flatMap(ids -> assignRoleIds(user, ids));
            }

            resolvedRoleIds = roleIds;
            return assignRoleIds(user, resolvedRoleIds);
        });
    }

    private Mono<User> assignRoleIds(User user, java.util.Collection<Long> roleIds) {
        return userRoleRepository.deleteByUserId(user.getId())
            .thenMany(Flux.fromIterable(roleIds))
            .flatMap(roleId -> roleRepository.findByIdAndIsDeletedFalse(roleId)
                .switchIfEmpty(Mono.error(new RuntimeException("Role not found: " + roleId))))
            .flatMap(role -> userRoleRepository.save(new UserRole(user.getId(), role.getId())))
            .then(Mono.just(user));
    }
    
    @Transactional
    public Mono<User> save(User user) {
        return userRepository.save(user);
    }

    /**
     * Load roles for the given user and set them to the user
     * @param user
     * @return
     */
    @Transactional
    private Mono<Void> loadUserRoles(User user) {
        return userRoleRepository.findByUserId(user.getId())
            .collectList()
            .flatMap(userRoles -> {
                if (userRoles.isEmpty()) {
                    user.setRoles(new HashSet<>());
                    return Mono.empty();
                }

                List<Long> roleIds = userRoles.stream()
                    .map(UserRole::getRoleId)
                    .distinct()
                    .toList();

                return roleRepository.findAllById(roleIds)
                    .collectMap(Role::getId)
                    .flatMap(roleMap -> rolePermissionRepository.findByRoleIdIn(roleIds)
                        .collectList()
                        .flatMap(rolePermissions -> {
                            Set<Long> permissionIds = rolePermissions.stream()
                                .map(RolePermission::getPermissionId)
                                .collect(Collectors.toSet());

                            if (permissionIds.isEmpty()) {
                                Set<Role> roles = roleMap.values().stream()
                                    .peek(role -> role.setPermissions(new HashSet<>()))
                                    .collect(Collectors.toCollection(HashSet::new));
                                user.setRoles(roles);
                                return Mono.empty();
                            }

                            return permissionRepository.findByIdIn(permissionIds)
                                .collectMap(permission -> permission.getId())
                                .map(permissionMap -> {
                                    Set<Role> roles = new HashSet<>();
                                    for (Long roleId : roleIds) {
                                        Role role = roleMap.get(roleId);
                                        if (role == null) {
                                            continue;
                                        }
                                        Set<Permission> permissions = rolePermissions.stream()
                                            .filter(rolePermission -> Objects.equals(rolePermission.getRoleId(), roleId))
                                            .map(RolePermission::getPermissionId)
                                            .map(permissionMap::get)
                                            .filter(Objects::nonNull)
                                            .collect(Collectors.toCollection(HashSet::new));
                                        role.setPermissions(permissions);
                                        roles.add(role);
                                    }
                                    user.setRoles(roles);
                                    return roles;
                                })
                                .then();
                        })
                    );
            });
    }

    /**
     * Create a new user with the given request data.
     * @param request The user creation request containing user details.
     * @return A Mono emitting the created UserResponse.
     */
    @Transactional
    public Mono<UserResponse> createUser(UserCreateRequest request) {
        return AuditUtil.getCurrentUserIdOrThrow()
            .flatMap(currentUserId -> ensureUniqueUserCredentials(request.getUsername(), request.getEmail())
                .then(Mono.defer(() -> {
                    User user = new User();
                    user.setFirstName(request.getFirstName());
                    user.setLastName(request.getLastName());
                    user.setUsername(request.getUsername());
                    user.setPassword(passwordEncoder != null ? passwordEncoder.encode(request.getPassword()) : request.getPassword());
                    user.setEmail(request.getEmail());
                    user.setPhoneNumber(request.getPhoneNumber());
                    user.setStatus(EnumStatus.ACTIVATED.getValue());
                    user.setIsDeleted(false);
                    user.setPublishedAt(LocalDateTime.now());
                    user.setPublishedId(currentUserId);

                    return userRepository.save(user)
                        .flatMap(savedUser -> assignUserRoles(savedUser, request.getRoles()));
                })))
            .flatMap(user -> loadUserRoles(user).thenReturn(user))
            .flatMap(this::mapUserToDto);
    }

    /**
     * Update an existing user with the given ID and request data.
     * @param id The ID of the user to update.
     * @param userResponse The user response containing updated user details.
     * @return A Mono emitting the updated UserResponse.
     */
    @Transactional
    public Mono<UserResponse> updateUser(Long id, UserResponse userResponse) {
        return AuditUtil.getCurrentUserIdOrThrow()
                .flatMap(currentUserId -> userRepository.findById(id)
                        .switchIfEmpty(Mono.error(new RuntimeException("User not found")))
                        .flatMap(user -> {
                            Mono<User> emailCheck;

                            if (userResponse.getEmail() != null &&
                                    !Objects.equals(userResponse.getEmail(), user.getEmail())) {
                                emailCheck = userRepository.findByEmailAndIsDeletedFalse(userResponse.getEmail())
                                    .flatMap(existsUser ->
                                        Mono.<User>error(new RuntimeException("Email already exists"))
                                    )
                                    .switchIfEmpty(Mono.just(user));
                            } else {
                                emailCheck = Mono.just(user);
                            }

                            return emailCheck.flatMap(updatedUser -> {
                                if (userResponse.getFirstName() != null) {
                                    updatedUser.setFirstName(userResponse.getFirstName());
                                }
                                if (userResponse.getLastName() != null) {
                                    updatedUser.setLastName(userResponse.getLastName());
                                }
                                if (userResponse.getEmail() != null) {
                                    updatedUser.setEmail(userResponse.getEmail());
                                }
                                if (userResponse.getPhoneNumber() != null) {
                                    updatedUser.setPhoneNumber(userResponse.getPhoneNumber());
                                }
                                if (userResponse.getStatus() != null) {
                                    try {
                                        updatedUser.applyStatus(EnumStatus.fromValue(userResponse.getStatus()).getValue());
                                    } catch (IllegalArgumentException ex) {
                                        return Mono.error(new RuntimeException("Invalid status: " + userResponse.getStatus()));
                                    }
                                }
                                if (userResponse.getIsDeleted() != null) {
                                    updatedUser.setIsDeleted(userResponse.getIsDeleted());
                                }

                                updatedUser.setModifiedAt(LocalDateTime.now());
                                updatedUser.setModifiedId(currentUserId);

                                return userRepository.save(updatedUser);
                            });
                        })
                        .flatMap(savedUser -> assignUserRoles(savedUser, userResponse.getRoles())))
                .flatMap(user -> loadUserRoles(user).thenReturn(user))
                .flatMap(this::mapUserToDto);
    }

    /**
     * Change the password for an active user.
     * @param id The ID of the user whose password should be changed.
     * @param newPassword The new plain-text password.
     * @param confirmNewPassword The confirmation of the new password.
     * @return A Mono indicating completion.
     */
    @Transactional
    public Mono<Void> changePassword(Long id, String newPassword, String confirmNewPassword) {
        if (!Objects.equals(newPassword, confirmNewPassword)) {
            return Mono.error(new IllegalArgumentException("New password and confirmation do not match"));
        }

        return AuditUtil.getCurrentUserIdOrThrow()
                .flatMap(currentUserId -> userRepository.findByIdAndIsDeletedFalse(id)
                        .switchIfEmpty(Mono.error(new RuntimeException("User not found with id: " + id)))
                        .flatMap(user -> {
                            user.setPassword(passwordEncoder.encode(newPassword));
                            user.setModifiedAt(LocalDateTime.now());
                            user.setModifiedId(currentUserId);
                            return userRepository.save(user);
                        }))
                .then();
    }
    
    /**
     * Delete a user by ID. Marks the user as deleted and updates the status.
     * @param id The ID of the user to delete.
     * @return A Mono indicating completion.
     */
    public Mono<Void> deleteUser(Long id) {
        return AuditUtil.getCurrentUserIdOrThrow()
            .flatMap(currentUserId -> userRepository.findByIdAndIsDeletedFalse(id)
                .switchIfEmpty(Mono.error(new RuntimeException("User not found with id: " + id)))
                .flatMap(user -> {
                    user.setIsDeleted(true);
                    user.setStatus(EnumStatus.DELETED.getValue());
                    user.setModifiedAt(LocalDateTime.now());
                    user.setModifiedId(currentUserId);
                    return userRepository.save(user);
                })
            )
            .then();
    }
    
    /**
     * Maps a User entity to a UserResponse DTO.
     * @param user The User entity to map.
     * @return A Mono emitting the mapped UserResponse.
     */
    private Mono<UserResponse> mapUserToDto(User user) {
        UserResponse dto = new UserResponse();
        dto.setId(user.getId());
        dto.setFirstName(user.getFirstName());
        dto.setLastName(user.getLastName());
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setPhoneNumber(user.getPhoneNumber());
        dto.setStatus(user.getStatus() != null ? String.valueOf(user.getStatus()) : null);
        dto.setIsDeleted(user.getIsDeleted());
        // Map roles to string names
        if (user.getRoles() != null) {
            dto.setRoles(user.getRoles().stream()
                .map(r -> r.getId())
                .collect(Collectors.toList()));
        }
        dto.setPublishedAt(user.getPublishedAt());
        dto.setModifiedAt(user.getModifiedAt());
        dto.setPublishedId(user.getPublishedId());
        dto.setModifiedId(user.getModifiedId());
        
        return Mono.just(dto);
    }
}