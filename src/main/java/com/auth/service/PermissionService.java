package com.auth.service;

import com.auth.dto.request.PermissionCreateRequest;
import com.auth.dto.response.PageResponse;
import com.auth.dto.response.PermissionResponse;
import com.auth.exception.DeletedExceptionHandler;
import com.auth.model.Permission;
import com.auth.repository.PermissionRepository;
import com.auth.util.AuditUtil;
import com.auth.util.EnumStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.List;

/**
 * @author Roeurt Kesei
 * Service for managing permissions.
 */
@Service
public class PermissionService {
    
    private final PermissionRepository permissionRepository;
    
    public PermissionService(PermissionRepository permissionRepository) {
        this.permissionRepository = permissionRepository;
    }
    
    @Transactional(readOnly = true)
    public Mono<PageResponse<PermissionResponse>> findAllPermissions(int page, int size) {
        long offset = (long) page * size;

        Mono<List<PermissionResponse>> permissions = permissionRepository.findAllByIsDeletedFalse(size, offset)
            .flatMap(this::mapPermissionToDto)
            .collectList();

        return Mono.zip(permissionRepository.countByIsDeletedFalse(), permissions)
            .map(result -> new PageResponse<>(
                result.getT2(),
                page,
                size,
                result.getT1()
            ));
    }
    
    @Transactional(readOnly = true)
    public Mono<PermissionResponse> findPermissionById(Long id) {
        return permissionRepository.findById(id)
                .switchIfEmpty(Mono.error(new RuntimeException("Permission not found with id: " + id)))
                .flatMap(permission -> {
                    if (Boolean.TRUE.equals(permission.getIsDeleted())) {
                        return Mono.error(new DeletedExceptionHandler(id));
                    }
                    return Mono.just(permission);
                })
                .flatMap(this::mapPermissionToDto);
    }
    
    @Transactional
    public Mono<PermissionResponse> createPermission(PermissionCreateRequest request) {
        return AuditUtil.getCurrentUserIdOrThrow()
            .flatMap(currentUserId -> permissionRepository.existsByName(request.getName())
                .flatMap(exists -> {
                    if (exists) {
                        return Mono.error(new RuntimeException("Permission already exists"));
                    }

                    Permission permission = new Permission();
                    permission.setName(request.getName());
                    permission.setDescription(request.getDescription());
                    permission.setStatus(EnumStatus.ACTIVATED.getValue());
                    permission.setIsDeleted(request.getIsDeleted() != null ? request.getIsDeleted() : false);

                    LocalDateTime now = LocalDateTime.now();
                    permission.setPublishedAt(now);
                    permission.setPublishedId(currentUserId);

                    return permissionRepository.save(permission);
                })
            )
            .flatMap(this::mapPermissionToDto);
    }
    
    @Transactional
    public Mono<PermissionResponse> updatePermission(Long id, PermissionResponse permissionResponse) {
        return AuditUtil.getCurrentUserIdOrThrow()
            .flatMap(currentUserId -> permissionRepository.findById(id)
                .switchIfEmpty(Mono.error(new RuntimeException("Permission not found")))
                .flatMap(existingPermission -> {
                    if (permissionResponse.getName() != null) {
                        existingPermission.setName(permissionResponse.getName());
                    }

                    if (permissionResponse.getDescription() != null) {
                        existingPermission.setDescription(permissionResponse.getDescription());
                    }

                    if (permissionResponse.getStatus() != null) {
                        try {
                            existingPermission.applyStatus(EnumStatus.fromValue(permissionResponse.getStatus()).getValue());
                        } catch (IllegalArgumentException ex) {
                            return Mono.error(new RuntimeException("Invalid status: " + permissionResponse.getStatus()));
                        }
                    }

                    if (permissionResponse.getIsDeleted() != null) {
                        existingPermission.setIsDeleted(permissionResponse.getIsDeleted());
                    }

                    existingPermission.setModifiedAt(LocalDateTime.now());
                    existingPermission.setModifiedId(currentUserId);

                    return permissionRepository.save(existingPermission);
                })
            )
            .flatMap(this::mapPermissionToDto);
    }
    
    @Transactional
    public Mono<Void> deletePermission(Long id) {
        return AuditUtil.getCurrentUserIdOrThrow()
            .flatMap(currentUserId -> permissionRepository.findByIdAndIsDeletedFalse(id)
                .switchIfEmpty(Mono.error(new RuntimeException("Permission not found with id: " + id)))
                .flatMap(permission -> {
                    permission.setIsDeleted(true);
                    permission.setStatus(EnumStatus.DELETED.getValue());
                    permission.setModifiedAt(LocalDateTime.now());
                    permission.setModifiedId(currentUserId);
                    return permissionRepository.save(permission);
                })
            )
            .then();
    }

    private Mono<PermissionResponse> mapPermissionToDto(Permission permission) {
        PermissionResponse dto = new PermissionResponse();
        dto.setId(permission.getId());
        dto.setName(permission.getName());
        dto.setDescription(permission.getDescription());
        dto.setStatus(permission.getStatus() != null ? String.valueOf(permission.getStatus()) : null);
        dto.setIsDeleted(permission.getIsDeleted());
        dto.setPublishedAt(permission.getPublishedAt());
        dto.setModifiedAt(permission.getModifiedAt());
        dto.setPublishedId(permission.getPublishedId());
        dto.setModifiedId(permission.getModifiedId());
        
        return Mono.just(dto);
    }
}