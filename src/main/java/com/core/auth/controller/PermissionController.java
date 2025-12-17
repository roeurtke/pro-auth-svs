package com.core.auth.controller;

import com.core.auth.constants.ApiPaths;
import com.core.auth.dto.request.PermissionCreateRequest;
import com.core.auth.dto.request.PermissionUpdateRequest;
import com.core.auth.dto.response.ApiResponse;
import com.core.auth.dto.response.PermissionResponse;
import com.core.auth.service.PermissionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping(ApiPaths.PERMISSIONS)
@RequiredArgsConstructor
@Tag(name = "Permission Management", description = "Permission management endpoints")
public class PermissionController {
    
    private final PermissionService permissionService;
    
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Get all permissions")
    public Mono<ApiResponse<Flux<PermissionResponse>>> getAllPermissions() {
        Flux<PermissionResponse> permissions = permissionService.findAll()
                .map(permissionService::mapToResponse);
        return Mono.just(ApiResponse.success("Permissions retrieved successfully", permissions));
    }
    
    @PostMapping
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('PERM_PERMISSION_MANAGE')")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Create a new permission")
    public Mono<ApiResponse<PermissionResponse>> createPermission(
            @Valid @RequestBody PermissionCreateRequest request) {
        
        return permissionService.createPermission(request)
                .map(permission -> ApiResponse.success("Permission created successfully", 
                        permissionService.mapToResponse(permission)));
    }
    
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('PERM_PERMISSION_MANAGE')")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Update a permission")
    public Mono<ApiResponse<PermissionResponse>> updatePermission(
            @PathVariable Long id,
            @Valid @RequestBody PermissionUpdateRequest request) {
        
        return permissionService.updatePermission(id, request)
                .map(permission -> ApiResponse.success("Permission updated successfully", 
                        permissionService.mapToResponse(permission)));
    }
    
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('PERM_PERMISSION_MANAGE')")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Delete a permission")
    public Mono<ApiResponse<Void>> deletePermission(@PathVariable Long id) {
        return permissionService.deletePermission(id)
                .thenReturn(ApiResponse.success("Permission deleted successfully", null));
    }
    
    @GetMapping("/category/{category}")
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Get permissions by category")
    public Mono<ApiResponse<Flux<PermissionResponse>>> getPermissionsByCategory(
            @PathVariable String category) {
        
        Flux<PermissionResponse> permissions = permissionService.findByCategory(category)
                .map(permissionService::mapToResponse);
        return Mono.just(ApiResponse.success("Permissions retrieved successfully", permissions));
    }
}