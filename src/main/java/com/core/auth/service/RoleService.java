package com.core.auth.service;

import com.core.auth.dto.request.RoleCreateRequest;
import com.core.auth.dto.request.RoleUpdateRequest;
import com.core.auth.dto.response.PermissionResponse;
import com.core.auth.dto.response.RoleResponse;
import com.core.auth.model.Permission;
import com.core.auth.model.Role;
import com.core.auth.model.User;
import com.core.auth.repository.RoleRepository;
import com.core.auth.repository.PermissionRepository;
import com.core.auth.repository.RolePermissionRepository;
import com.core.auth.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class RoleService {
    
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRoleRepository userRoleRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final AuditLogService auditLogService;
    
    public Mono<Role> findById(Long id) {
        return roleRepository.findById(id);
    }
    
    public Mono<Role> findByName(String name) {
        return roleRepository.findByName(name);
    }
    
    public Mono<Role> findByCode(String code) {
        return roleRepository.findByCode(code);
    }
    
    public Flux<Role> findAll() {
        return roleRepository.findAll();
    }
    
    public Flux<Role> findByUserId(Long userId) {
        return roleRepository.findByUserId(userId);
    }
    
    @Transactional
    public Mono<Role> createRole(RoleCreateRequest request) {
        return roleRepository.existsByCode(request.getCode())
                .flatMap(exists -> {
                    if (exists) {
                        return Mono.error(new RuntimeException("Role code already exists"));
                    }
                    
                    Role role = Role.builder()
                            .name(request.getName())
                            .code(request.getCode())
                            .description(request.getDescription())
                            .systemRole(false)
                            .createdAt(LocalDateTime.now())
                            .updatedAt(LocalDateTime.now())
                            .build();
                    
                    return roleRepository.save(role)
                            .flatMap(savedRole -> {
                                if (request.getPermissionIds() != null && !request.getPermissionIds().isEmpty()) {
                                    return assignPermissionsToRole(savedRole.getId(), request.getPermissionIds())
                                            .thenReturn(savedRole);
                                }
                                return Mono.just(savedRole);
                            })
                            .doOnSuccess(r -> 
                                auditLogService.logRoleCreation(r.getId(), r.getName())
                            );
                });
    }
    
    @Transactional
    public Mono<Role> updateRole(Long roleId, RoleUpdateRequest request) {
        return findById(roleId)
                .flatMap(role -> {
                    if (role.isSystemRole()) {
                        return Mono.error(new RuntimeException("System roles cannot be modified"));
                    }
                    
                    if (request.getName() != null) {
                        role.setName(request.getName());
                    }
                    if (request.getDescription() != null) {
                        role.setDescription(request.getDescription());
                    }
                    role.setUpdatedAt(LocalDateTime.now());
                    
                    return roleRepository.save(role)
                            .flatMap(savedRole -> {
                                if (request.getPermissionIds() != null) {
                                    return updateRolePermissions(savedRole.getId(), request.getPermissionIds())
                                            .thenReturn(savedRole);
                                }
                                return Mono.just(savedRole);
                            })
                            .doOnSuccess(r -> 
                                auditLogService.logRoleUpdate(roleId, "Role updated")
                            );
                });
    }
    
    @Transactional
    public Mono<Void> deleteRole(Long roleId) {
        return findById(roleId)
                .flatMap(role -> {
                    if (role.isSystemRole()) {
                        return Mono.error(new RuntimeException("System roles cannot be deleted"));
                    }
                    
                    return userRoleRepository.deleteByRoleId(roleId)
                            .then(rolePermissionRepository.deleteByRoleId(roleId))
                            .then(roleRepository.delete(role))
                            .doOnSuccess(v -> 
                                auditLogService.logRoleDeletion(roleId, role.getName())
                            );
                });
    }
    
    @Transactional
    public Mono<Void> assignRoleToUser(Long userId, Long roleId) {
        return userRoleRepository.findByUserIdAndRoleId(userId, roleId)
                .flatMap(existing -> 
                    Mono.error(new RuntimeException("User already has this role"))
                )
                .switchIfEmpty(Mono.defer(() -> 
                    userRoleRepository.save(new com.core.auth.model.UserRole(userId, roleId))
                        .doOnSuccess(v -> 
                            auditLogService.logRoleAssignment(userId, roleId)
                        )
                ))
                .then();
    }
    
    @Transactional
    public Mono<Void> removeRoleFromUser(Long userId, Long roleId) {
        return userRoleRepository.deleteByUserIdAndRoleId(userId, roleId)
                .doOnSuccess(v -> 
                    auditLogService.logRoleRemoval(userId, roleId)
                );
    }
    
    @Transactional
    public Mono<Void> assignPermissionsToRole(Long roleId, Set<Long> permissionIds) {
        return Flux.fromIterable(permissionIds)
                .flatMap(permissionId -> 
                    rolePermissionRepository.save(new com.core.auth.model.RolePermission(roleId, permissionId))
                )
                .then()
                .doOnSuccess(v -> 
                    auditLogService.logPermissionsAssignment(roleId, permissionIds)
                );
    }
    
    @Transactional
    public Mono<Void> updateRolePermissions(Long roleId, Set<Long> permissionIds) {
        return rolePermissionRepository.deleteByRoleId(roleId)
                .then(assignPermissionsToRole(roleId, permissionIds));
    }
    
    @Transactional
    public Mono<Void> assignDefaultRole(Long userId) {
        return findByName("USER")
                .switchIfEmpty(createDefaultUserRole())
                .flatMap(role -> assignRoleToUser(userId, role.getId()));
    }
    
    private Mono<Role> createDefaultUserRole() {
        Role userRole = Role.builder()
                .name("User")
                .code("USER")
                .description("Default user role")
                .systemRole(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        
        return roleRepository.save(userRole);
    }
    
    public Mono<User> getUserWithAuthorities(Long userId) {
        return Mono.zip(
                getUserRoles(userId),
                getUserPermissions(userId)
        ).map(tuple -> {
            User user = new User();
            user.setId(userId);
            user.setRoles(tuple.getT1());
            user.setPermissions(tuple.getT2());
            return user;
        });
    }
    
    private Mono<Set<Role>> getUserRoles(Long userId) {
        return roleRepository.findByUserId(userId)
                .collectList()
                .map(HashSet::new);
    }
    
    private Mono<Set<Permission>> getUserPermissions(Long userId) {
        return permissionRepository.findByUserId(userId)
                .collectList()
                .map(HashSet::new);
    }
    
    public Set<GrantedAuthority> getAuthoritiesForUser(Long userId) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        
        // Add role authorities
        roleRepository.findByUserId(userId)
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getCode()))
                .subscribe(authorities::add);
        
        // Add permission authorities
        permissionRepository.findByUserId(userId)
                .map(permission -> new SimpleGrantedAuthority("PERM_" + permission.getCode()))
                .subscribe(authorities::add);
        
        return authorities;
    }
    
    public RoleResponse mapToResponse(Role role) {
        return RoleResponse.builder()
                .id(role.getId())
                .name(role.getName())
                .code(role.getCode())
                .description(role.getDescription())
                .systemRole(role.isSystemRole())
                .createdAt(role.getCreatedAt())
                .permissions(mapPermissionsToResponse(role.getPermissions()))
                .build();
    }
    
    public Set<RoleResponse> mapRolesToResponse(Set<Role> roles) {
        return roles.stream()
                .map(this::mapToResponse)
                .collect(Collectors.toSet());
    }
    
    public PermissionResponse mapToResponse(Permission permission) {
        return PermissionResponse.builder()
                .id(permission.getId())
                .name(permission.getName())
                .code(permission.getCode())
                .description(permission.getDescription())
                .category(permission.getCategory())
                .createdAt(permission.getCreatedAt())
                .build();
    }
    
    public Set<PermissionResponse> mapPermissionsToResponse(Set<Permission> permissions) {
        return permissions.stream()
                .map(this::mapToResponse)
                .collect(Collectors.toSet());
    }
}