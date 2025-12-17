package com.core.auth.controller;

import com.core.auth.constants.ApiPaths;
import com.core.auth.dto.request.UserUpdateRequest;
import com.core.auth.dto.response.ApiResponse;
import com.core.auth.dto.response.UserResponse;
import com.core.auth.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping(ApiPaths.USERS)
@RequiredArgsConstructor
@Tag(name = "User Management", description = "User management endpoints")
public class UserController {
    
    private final UserService userService;
    
    @GetMapping(ApiPaths.ME)
    @PreAuthorize("isAuthenticated()")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Get current user profile")
    public Mono<ApiResponse<UserResponse>> getCurrentUser(@RequestParam Long userId) {
        return userService.getUserWithDetails(userId)
                .map(response -> ApiResponse.success("User retrieved successfully", response));
    }
    
    @PutMapping(ApiPaths.UPDATE_PROFILE)
    @PreAuthorize("isAuthenticated()")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Update user profile")
    public Mono<ApiResponse<UserResponse>> updateProfile(
            @RequestParam Long userId,
            @Valid @RequestBody UserUpdateRequest request) {
        
        return userService.update(userId, request)
                .map(user -> ApiResponse.success("Profile updated successfully", 
                        userService.mapToResponse(user)));
    }
    
    @PostMapping(ApiPaths.CHANGE_PASSWORD)
    @PreAuthorize("isAuthenticated()")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Change user password")
    public Mono<ApiResponse<Void>> changePassword(
            @RequestParam Long userId,
            @RequestParam String oldPassword,
            @RequestParam String newPassword) {
        
        return userService.changePassword(userId, oldPassword, newPassword)
                .thenReturn(ApiResponse.success("Password changed successfully", null));
    }
    
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Get user by ID (Admin only)")
    public Mono<ApiResponse<UserResponse>> getUserById(@PathVariable Long id) {
        return userService.getUserWithDetails(id)
                .map(response -> ApiResponse.success("User retrieved successfully", response));
    }
}