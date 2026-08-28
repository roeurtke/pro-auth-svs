package com.auth.service;

import com.auth.dto.request.RoleCreateRequest;
import com.auth.dto.response.RoleResponse;
import com.auth.exception.DeletedExceptionHandler;
import com.auth.model.Permission;
import com.auth.model.Role;
import com.auth.model.RolePermission;
import com.auth.repository.PermissionRepository;
import com.auth.repository.RoleRepository;
import com.auth.repository.RolePermissionRepository;
import com.auth.util.AuditUtil;
import com.auth.util.EnumStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.stream.Collectors;

/**
 * @author Roeurt Kesei
 * Service for managing roles.
 */
@Service
public class RoleService {
    
    private final RoleRepository roleRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final PermissionRepository permissionRepository;
    
    public RoleService(
        RoleRepository roleRepository,
        RolePermissionRepository rolePermissionRepository,
        PermissionRepository permissionRepository
    ) {
        this.roleRepository = roleRepository;
        this.rolePermissionRepository = rolePermissionRepository;
        this.permissionRepository = permissionRepository;
    }
    
    @Transactional
    public Flux<RoleResponse> findAllRoles() {
        return roleRepository.findAllByIsDeletedFalse()
                .flatMap(role -> loadRolePermissions(role).thenReturn(role))
                .flatMap(this::mapRoleToDto);
    }
    
    @Transactional
    public Mono<RoleResponse> findRoleById(Long id) {
        return roleRepository.findById(id)
                .switchIfEmpty(Mono.error(new RuntimeException("Role not found with id: " + id)))
                .flatMap(role -> {
                    if (Boolean.TRUE.equals(role.getIsDeleted())) {
                        return Mono.error(new DeletedExceptionHandler(id));
                    }
                    return loadRolePermissions(role).thenReturn(role);
                })
                .flatMap(this::mapRoleToDto);
    }
    
    @Transactional
    private Mono<Void> loadRolePermissions(Role role) {
        return rolePermissionRepository.findPermissionByRoleId(role.getId())
                .map(RolePermission::getPermissionId)
                .collectList()
                .flatMap(permissionIds -> {
                    if (permissionIds.isEmpty()) {
                        role.setPermissions(java.util.Collections.emptySet());
                        return Mono.empty();
                    }
                    return permissionRepository.findByIdIn(permissionIds)
                            .collect(Collectors.toSet())
                            .doOnNext(permissions -> role.setPermissions(new java.util.HashSet<>(permissions)))
                            .then();
                });
    }

    private Mono<Permission> resolvePermission(Long id, String name) {
        if (id != null) {
            return permissionRepository.findById(id)
                .switchIfEmpty(Mono.error(new RuntimeException("Permission not found with ID: " + id)));
        }

        if (name != null) {
            return permissionRepository.findByName(name)
                .switchIfEmpty(Mono.error(new RuntimeException("Permission not found: " + name)));
        }

        return Mono.error(new RuntimeException("Permission must have either id or name"));
    }

    private Mono<Role> saveRolePermissions(Role role, java.util.Set<RoleCreateRequest.PermissionRequest> permissionRequests) {
        if (permissionRequests == null || permissionRequests.isEmpty()) {
            return Mono.just(role);
        }

        return Flux.fromIterable(permissionRequests)
            .flatMap(permissionRequest -> resolvePermission(permissionRequest.getId(), permissionRequest.getName()))
            .flatMap(permission -> rolePermissionRepository.save(new RolePermission(role.getId(), permission.getId())))
            .then(Mono.just(role));
    }

    private Mono<Void> replaceRolePermissions(Long roleId, java.util.Set<Permission> permissions) {
        if (permissions == null || permissions.isEmpty()) {
            return rolePermissionRepository.deleteByRoleId(roleId);
        }

        return rolePermissionRepository.deleteByRoleId(roleId)
            .thenMany(Flux.fromIterable(permissions))
            .flatMap(permission -> {
                if (permission.getId() != null) {
                    return permissionRepository.findById(permission.getId())
                        .switchIfEmpty(Mono.error(new RuntimeException("Permission not found with ID: " + permission.getId())));
                }
                if (permission.getName() != null) {
                    return permissionRepository.findByName(permission.getName())
                        .switchIfEmpty(Mono.error(new RuntimeException("Permission not found: " + permission.getName())));
                }
                return Mono.error(new RuntimeException("Permission must have either id or name"));
            })
            .flatMap(permission -> rolePermissionRepository.save(new RolePermission(roleId, permission.getId())))
            .then();
    }
    
    @Transactional
    public Mono<RoleResponse> createRole(RoleCreateRequest request) {
        return AuditUtil.getCurrentUserIdOrThrow()
            .flatMap(currentUserId -> roleRepository.existsByName(request.getName())
                .flatMap(exists -> {
                    if (exists) {
                        return Mono.error(new RuntimeException("Role already exists"));
                    }

                    Role role = new Role();
                    role.setName(request.getName());
                    role.setDescription(request.getDescription());
                    role.setStatus(EnumStatus.ACTIVATED.getValue());
                    role.setIsDeleted(request.getIsDeleted() != null ? request.getIsDeleted() : false);

                    LocalDateTime now = LocalDateTime.now();
                    role.setPublishedAt(now);
                    role.setPublishedId(currentUserId);

                    return roleRepository.save(role)
                        .flatMap(savedRole -> saveRolePermissions(savedRole, request.getPermissions()));
                })
            )
            .flatMap(savedRole -> loadRolePermissions(savedRole).thenReturn(savedRole))
            .flatMap(this::mapRoleToDto);
    }
    
    @Transactional
    public Mono<RoleResponse> updateRole(Long id, RoleResponse roleResponse) {
        return AuditUtil.getCurrentUserIdOrThrow()
            .flatMap(currentUserId -> roleRepository.findById(id)
                .switchIfEmpty(Mono.error(new RuntimeException("Role not found or is deleted")))
                .flatMap(existingRole -> {
                    // Update name if provided
                    if (roleResponse.getName() != null) {
                        existingRole.setName(roleResponse.getName());
                    }
                    
                    // Update description if provided
                    if (roleResponse.getDescription() != null) {
                        existingRole.setDescription(roleResponse.getDescription());
                    }
                    
                    // Update status (enum name only)
                    if (roleResponse.getStatus() != null) {
                        try {
                            existingRole.applyStatus(EnumStatus.fromValue(roleResponse.getStatus()).getValue());
                        } catch (IllegalArgumentException ex) {
                            return Mono.error(
                                    new RuntimeException("Invalid status: " + roleResponse.getStatus())
                            );
                        }
                    }
                    
                    // Soft delete toggle
                    if (roleResponse.getIsDeleted() != null) {
                        existingRole.setIsDeleted(roleResponse.getIsDeleted());
                    }
                    
                    existingRole.setModifiedAt(LocalDateTime.now());
                    existingRole.setModifiedId(currentUserId);
                    
                    return roleRepository.save(existingRole);
                })
                .flatMap(savedRole -> {
                    if (roleResponse.getPermissions() != null) {
                        return replaceRolePermissions(id, roleResponse.getPermissions())
                            .thenReturn(savedRole);
                    }
                    return Mono.just(savedRole);
                })
            )
            .flatMap(savedRole -> loadRolePermissions(savedRole).thenReturn(savedRole))
            .flatMap(this::mapRoleToDto);
    }
    
    @Transactional
    public Mono<Void> deleteRole(Long id) {
        return AuditUtil.getCurrentUserIdOrThrow()
            .flatMap(currentUserId -> roleRepository.findByIdAndIsDeletedFalse(id)
                .switchIfEmpty(Mono.error(new RuntimeException("Role not found with id: " + id)))
                .flatMap(role -> {
                    role.setIsDeleted(true);
                    role.setStatus(EnumStatus.DELETED.getValue());
                    role.setModifiedAt(LocalDateTime.now());
                    role.setModifiedId(currentUserId);
                    return roleRepository.save(role);
                })
            )
            .then();
    }

    private Mono<RoleResponse> mapRoleToDto(Role role) {
        RoleResponse dto = new RoleResponse();
        dto.setId(role.getId());
        dto.setName(role.getName());
        dto.setDescription(role.getDescription());
        dto.setStatus(role.getStatus() != null ? String.valueOf(role.getStatus()) : null);
        dto.setIsDeleted(role.getIsDeleted());
        dto.setPermissions(role.getPermissions());
        dto.setPublishedAt(role.getPublishedAt());
        dto.setModifiedAt(role.getModifiedAt());
        dto.setPublishedId(role.getPublishedId());
        dto.setModifiedId(role.getModifiedId());
        
        return Mono.just(dto);
    }
}