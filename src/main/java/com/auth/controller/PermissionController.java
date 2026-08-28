package com.auth.controller;

import com.auth.dto.request.PermissionCreateRequest;
import com.auth.dto.response.ApiResponse;
import com.auth.dto.response.PageResponse;
import com.auth.dto.response.PermissionResponse;
import com.auth.service.PermissionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

/**
 * @author Roeurt Kesei
 * Permission management REST controller.
 */
@RestController
@Validated
@RequestMapping("${api.base}/user_mod/permissions")
@Tag(name = "Permissions", description = "Permission management endpoints")
@SecurityRequirement(name = "bearerAuth")
public class PermissionController {
    
    private final PermissionService permissionService;
    
    public PermissionController(PermissionService permissionService) {
        this.permissionService = permissionService;
    }
    
    @GetMapping
    @PreAuthorize("hasAuthority('PERMISSION_READ')")
    @Operation(summary = "Get permissions",
        description = "Retrieve a paginated list of permissions (requires PERMISSION_READ permission and ADMIN role)")
    public Mono<PageResponse<PermissionResponse>> getAllPermissions(
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "10") @Min(1) @Max(100) int size
    ) {
        return permissionService.findAllPermissions(page, size);
    }
    
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('PERMISSION_READ')")
    @Operation(summary = "Get permission by ID", 
        description = "Retrieve permission by ID (requires PERMISSION_READ permission and ADMIN role)")
    public Mono<PermissionResponse> getPermissionById(@PathVariable Long id) {
        return permissionService.findPermissionById(id);
    }
    
    @PostMapping
    @PreAuthorize("hasAuthority('PERMISSION_WRITE')")
    @Operation(summary = "Create permission", 
        description = "Create a new permission (requires PERMISSION_WRITE permission and ADMIN role)")
    public Mono<ApiResponse<PermissionResponse>> createPermission(@Valid @RequestBody PermissionCreateRequest request) {
        return permissionService.createPermission(request)
                .map(permissionResponse -> ApiResponse.success("Permission is created successfully.", permissionResponse));
    }
    
    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('PERMISSION_WRITE')")
    @Operation(summary = "Update permission", 
        description = "Update permission information (requires PERMISSION_WRITE permission and ADMIN role)")
    public Mono<ApiResponse<PermissionResponse>> updatePermission(@PathVariable Long id, @Valid @RequestBody PermissionResponse permissionResponse) {
        return permissionService.updatePermission(id, permissionResponse)
                .map(updatedResponse -> ApiResponse.success("Permission is updated successfully.", updatedResponse));
    }
    
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('PERMISSION_DELETE')")
    @Operation(summary = "Delete permission", 
        description = "Delete permission (requires PERMISSION_DELETE permission and ADMIN role)")
    public Mono<ApiResponse<Void>> deletePermission(@PathVariable Long id) {
        return permissionService.deletePermission(id)
                .thenReturn(ApiResponse.success("Permission is deleted successfully.", null));
    }
}