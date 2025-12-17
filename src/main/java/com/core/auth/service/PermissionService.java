package com.core.auth.service;

import com.core.auth.dto.request.PermissionCreateRequest;
import com.core.auth.dto.request.PermissionUpdateRequest;
import com.core.auth.dto.response.PermissionResponse;
import com.core.auth.model.Permission;
import com.core.auth.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class PermissionService {
    
    private final PermissionRepository permissionRepository;
    private final AuditLogService auditLogService;
    
    public Mono<Permission> findById(Long id) {
        return permissionRepository.findById(id);
    }
    
    public Mono<Permission> findByCode(String code) {
        return permissionRepository.findByCode(code);
    }
    
    public Flux<Permission> findAll() {
        return permissionRepository.findAll();
    }
    
    public Flux<Permission> findByCategory(String category) {
        return permissionRepository.findByCategory(category);
    }
    
    public Flux<Permission> findByRoleId(Long roleId) {
        return permissionRepository.findByRoleId(roleId);
    }
    
    @Transactional
    public Mono<Permission> createPermission(PermissionCreateRequest request) {
        return permissionRepository.findByCode(request.getCode())
                .flatMap(existing -> 
                    Mono.<Permission>error(new RuntimeException("Permission code already exists"))
                )
                .switchIfEmpty(Mono.defer(() -> {
                    Permission permission = Permission.builder()
                            .name(request.getName())
                            .code(request.getCode())
                            .description(request.getDescription())
                            .category(request.getCategory())
                            .createdAt(LocalDateTime.now())
                            .updatedAt(LocalDateTime.now())
                            .build();
                    
                    return permissionRepository.save(permission)
                            .doOnSuccess(p -> 
                                auditLogService.logPermissionCreation(p.getId(), p.getName())
                            );
                }));
    }
    
    @Transactional
    public Mono<Permission> updatePermission(Long permissionId, PermissionUpdateRequest request) {
        return findById(permissionId)
                .flatMap(permission -> {
                    if (request.getName() != null) {
                        permission.setName(request.getName());
                    }
                    if (request.getDescription() != null) {
                        permission.setDescription(request.getDescription());
                    }
                    if (request.getCategory() != null) {
                        permission.setCategory(request.getCategory());
                    }
                    permission.setUpdatedAt(LocalDateTime.now());
                    
                    return permissionRepository.save(permission)
                            .doOnSuccess(p -> 
                                auditLogService.logPermissionUpdate(permissionId, "Permission updated")
                            );
                });
    }
    
    @Transactional
    public Mono<Void> deletePermission(Long permissionId) {
        return findById(permissionId)
                .flatMap(permission -> 
                    permissionRepository.delete(permission)
                            .doOnSuccess(v -> 
                                auditLogService.logPermissionDeletion(permissionId, permission.getName())
                            )
                );
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
}