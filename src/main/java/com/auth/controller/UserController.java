package com.auth.controller;

import com.auth.dto.request.UserCreateRequest;
import com.auth.dto.request.UserPasswordChangeRequest;
import com.auth.dto.response.ApiResponse;
import com.auth.dto.response.PageResponse;
import com.auth.dto.response.UserResponse;
import com.auth.service.UserService;
import com.auth.util.AuditUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.validation.annotation.Validated;
import reactor.core.publisher.Mono;

/**
 * @author Roeurt Kesei
 * User management REST controller.
 */
@RestController
@Validated
@RequestMapping("${api.base}/user_mod/users")
@Tag(name = "Users", description = "User management endpoints")
@SecurityRequirement(name = "bearerAuth")
public class UserController {
    
    private final UserService userService;
    
    public UserController(UserService userService) {
        this.userService = userService;
    }
    
    @PostMapping
    @PreAuthorize("hasAuthority('USER_WRITE')")
    @Operation(summary = "Create new user",
            description = "Create a new user (requires USER_WRITE permission)")
    public Mono<ApiResponse<UserResponse>> createUser(@Valid @RequestBody UserCreateRequest request) {
        return userService.createUser(request)
                .map(userResponse -> ApiResponse.success("User is created successfully.", userResponse));
    }

    @GetMapping("/profile")
    @Operation(summary = "Get current user profile",
        description = "Retrieve the authenticated user's profile")
    public Mono<UserResponse> getCurrentUserProfile() {
    return AuditUtil.getCurrentUserIdOrThrow()
        .flatMap(userService::findUserById);
    }
    
    @GetMapping
    @PreAuthorize("hasAuthority('USER_READ')")
    @Operation(summary = "Get users",
        description = "Retrieve a paginated list of users (requires USER_READ permission)")
    public Mono<PageResponse<UserResponse>> getAllUsers(
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "10") @Min(1) @Max(100) int size
    ) {
        return userService.findAllUsers(page, size);
    }
    
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('USER_READ')")
    @Operation(summary = "Get user by ID", 
        description = "Retrieve user by ID (requires USER_READ permission)")
    public Mono<UserResponse> getUserById(@PathVariable Long id) {
        return userService.findUserById(id);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('USER_WRITE')")
    @Operation(summary = "Update user", 
        description = "Update user information (requires USER_WRITE permission)")
    public Mono<ApiResponse<UserResponse>> updateUser(@PathVariable Long id, @Valid @RequestBody UserResponse userResponse) {
        return userService.updateUser(id, userResponse)
                .map(dto -> ApiResponse.success("User is updated successfully.", dto));
    }

    @PutMapping("/{id}/password")
    @PreAuthorize("hasAuthority('USER_WRITE')")
    @Operation(summary = "Change user password",
            description = "Change a user's password (requires USER_WRITE permission)")
    public Mono<ApiResponse<Void>> changePassword(
            @PathVariable Long id,
            @Valid @RequestBody UserPasswordChangeRequest request
    ) {
        return userService.changePassword(id, request.getNewPassword(), request.getConfirmNewPassword())
            .thenReturn(ApiResponse.success("User's password is changed successfully.", null));
    }
    
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('USER_DELETE')")
    @Operation(summary = "Delete user", 
        description = "Delete user (requires USER_DELETE permission)")
    public Mono<ApiResponse<Void>> deleteUser(@PathVariable Long id) {
        return userService.deleteUser(id)
                .thenReturn(ApiResponse.success("User is deleted successfully.", null));
    }
}