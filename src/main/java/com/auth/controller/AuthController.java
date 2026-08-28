package com.auth.controller;

import com.auth.dto.request.AuthRequest;
import com.auth.dto.request.RefreshTokenRequest;
import com.auth.dto.request.RegisterRequest;
import com.auth.dto.request.PasswordResetConfirmRequest;
import com.auth.dto.request.PasswordResetRequest;
import com.auth.dto.response.ApiResponse;
import com.auth.dto.response.AuthResponse;
import com.auth.service.AuthService;
import com.auth.service.PasswordResetService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

/**
 * @author Roeurt Kesei
 * Controller for handling authentication-related endpoints such as registration,
 * login, and token refresh.
 */
@RestController
@RequestMapping("${api.base}/auth_mod")
@Tag(name = "Authentication", description = "Authentication endpoints")
public class AuthController {
    
    private final AuthService authService;
    private final PasswordResetService passwordResetService;
    
    public AuthController(AuthService authService, PasswordResetService passwordResetService) {
        this.authService = authService;
        this.passwordResetService = passwordResetService;
    }
    
    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Register a new user", 
        description = "Creates a new user account with USER role")
    public Mono<ApiResponse<Void>> register(@Valid @RequestBody RegisterRequest request) {
        return authService.register(request)
                .thenReturn(ApiResponse.success("User is registered successfully.", null));
    }
    
    @PostMapping("/login")
    @Operation(summary = "Authenticate user", 
        description = "Authenticates user and returns JWT tokens")
    public Mono<ApiResponse<AuthResponse>> login(@Valid @RequestBody AuthRequest request) {
        return authService.authenticate(request)
                .map(authResponse -> ApiResponse.success("User has been authenticated successfully.", authResponse));
    }
    
    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token", 
        description = "Generates new access token using refresh token")
    public Mono<ApiResponse<AuthResponse>> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.refreshToken(request.getRefreshToken())
                .map(authResponse -> ApiResponse.success("Access Token has been refresh successfully.", authResponse));
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Send password reset code", description = "Sends a four-digit verification code to the user's email")
    public Mono<ApiResponse<Void>> forgotPassword(@Valid @RequestBody PasswordResetRequest request) {
        return passwordResetService.sendCode(request.getEmail())
                .thenReturn(ApiResponse.success("The verification code has been sent.", null));
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Reset password", description = "Verifies the email code and sets a new password")
    public Mono<ApiResponse<Void>> resetPassword(@Valid @RequestBody PasswordResetConfirmRequest request) {
        return passwordResetService.resetPassword(
                        request.getEmail(),
                        request.getVerificationCode(),
                        request.getNewPassword(),
                        request.getConfirmNewPassword())
                .thenReturn(ApiResponse.success("Password has been reset successfully.", null));
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout user",
        description = "Logs out the user and invalidates the access and refresh tokens")
    public Mono<ApiResponse<Void>> logout(
            @RequestHeader(value = "Authorization", required = false) String authorizationHeader,
            @RequestBody(required = false) RefreshTokenRequest request
    ) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return Mono.error(new RuntimeException("Invalid authorization header"));
        }

        String accessToken = authorizationHeader.substring("Bearer ".length());
        String refreshToken = request == null ? null : request.getRefreshToken();

        return authService.logout(accessToken, refreshToken)
                .thenReturn(ApiResponse.success("User has been logged out.", null));
    }
}