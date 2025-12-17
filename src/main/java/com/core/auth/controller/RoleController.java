package com.core.auth.controller;

import com.core.auth.constants.ApiPaths;
import com.core.auth.dto.request.RoleCreateRequest;
import com.core.auth.dto.request.RoleUpdateRequest;
import com.core.auth.dto.response.ApiResponse;
import com.core.auth.dto.response.RoleResponse;
import com.core.auth.service.RoleService;
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
@RequestMapping(ApiPaths.ROLES)
@RequiredArgsConstructor
@Tag(name = "Role Management", description = "Role management endpoints")
public class RoleController {
    
    private final RoleService roleService;
    
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Get all roles")
    public Mono<ApiResponse<Flux<RoleResponse>>> getAllRoles() {
        Flux<RoleResponse> roles = roleService.findAll()
                .map(roleService::mapToResponse);
        return Mono.just(ApiResponse.success("Roles retrieved successfully", roles));
    }
    
    @PostMapping
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('PERM_ROLE_MANAGE')")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Create a new role")
    public Mono<ApiResponse<RoleResponse>> createRole(@Valid @RequestBody RoleCreateRequest request) {
        return roleService.createRole(request)
                .map(role -> ApiResponse.success("Role created successfully", 
                        roleService.mapToResponse(role)));
    }
    
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('PERM_ROLE_MANAGE')")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Update a role")
    public Mono<ApiResponse<RoleResponse>> updateRole(
            @PathVariable Long id,
            @Valid @RequestBody RoleUpdateRequest request) {
        
        return roleService.updateRole(id, request)
                .map(role -> ApiResponse.success("Role updated successfully", 
                        roleService.mapToResponse(role)));
    }
    
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('PERM_ROLE_MANAGE')")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Delete a role")
    public Mono<ApiResponse<Void>> deleteRole(@PathVariable Long id) {
        return roleService.deleteRole(id)
                .thenReturn(ApiResponse.success("Role deleted successfully", null));
    }
    
    @PostMapping("/{roleId}/users/{userId}")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('PERM_USER_MANAGE')")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Assign role to user")
    public Mono<ApiResponse<Void>> assignRoleToUser(
            @PathVariable Long roleId,
            @PathVariable Long userId) {
        
        return roleService.assignRoleToUser(userId, roleId)
                .thenReturn(ApiResponse.success("Role assigned successfully", null));
    }
    
    @DeleteMapping("/{roleId}/users/{userId}")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('PERM_USER_MANAGE')")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Remove role from user")
    public Mono<ApiResponse<Void>> removeRoleFromUser(
            @PathVariable Long roleId,
            @PathVariable Long userId) {
        
        return roleService.removeRoleFromUser(userId, roleId)
                .thenReturn(ApiResponse.success("Role removed successfully", null));
    }
    
    @PostMapping("/{roleId}/permissions")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('PERM_ROLE_MANAGE')")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Assign permissions to role")
    public Mono<ApiResponse<Void>> assignPermissionsToRole(
            @PathVariable Long roleId,
            @RequestBody java.util.Set<Long> permissionIds) {
        
        return roleService.assignPermissionsToRole(roleId, permissionIds)
                .thenReturn(ApiResponse.success("Permissions assigned successfully", null));
    }
}