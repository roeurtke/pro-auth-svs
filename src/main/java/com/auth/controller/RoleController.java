package com.auth.controller;

import com.auth.dto.request.RoleCreateRequest;
import com.auth.dto.response.ApiResponse;
import com.auth.dto.response.RoleResponse;
import com.auth.service.RoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * @author Roeurt Kesei
 * Role management REST controller.
 */
@RestController
@RequestMapping("${api.base}/user_mod/roles")
@Tag(name = "Roles", description = "Role management endpoints")
@SecurityRequirement(name = "bearerAuth")
public class RoleController {
    
    private final RoleService roleService;
    
    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }
    
    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_READ')")
    @Operation(summary = "Get all roles", 
        description = "Retrieve all roles (requires ROLE_READ permission and ADMIN role)")
    public Flux<RoleResponse> getAllRoles() {
        return roleService.findAllRoles();
    }
    
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_READ')")
    @Operation(summary = "Get role by ID", 
        description = "Retrieve role by ID (requires ROLE_READ permission and ADMIN role)")
    public Mono<RoleResponse> getRoleById(@PathVariable Long id) {
        return roleService.findRoleById(id);
    }
    
    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_WRITE')")
    @Operation(summary = "Create role", 
        description = "Create a new role (requires ROLE_WRITE permission and ADMIN role)")
    public Mono<ApiResponse<RoleResponse>> createRole(@Valid @RequestBody RoleCreateRequest request) {
        return roleService.createRole(request)
                .map(roleResponse -> ApiResponse.success("Role is created successfully.", roleResponse));
    }
    
    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_WRITE')")
    @Operation(summary = "Update role", 
        description = "Update role information (requires ROLE_WRITE permission and ADMIN role)")
    public Mono<ApiResponse<RoleResponse>> updateRole(@PathVariable Long id, @Valid @RequestBody RoleResponse roleResponse) {
        return roleService.updateRole(id, roleResponse)
                .map(dto -> ApiResponse.success("Role is updated successfully.", dto));
    }
    
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_DELETE')")
    @Operation(summary = "Delete role", 
        description = "Delete role (requires ROLE_DELETE permission and ADMIN role)")
    public Mono<ApiResponse<Void>> deleteRole(@PathVariable Long id) {
        return roleService.deleteRole(id)
                .thenReturn(ApiResponse.success("Role is deleted successfully.", null));
    }
}