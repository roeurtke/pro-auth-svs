package com.core.auth.controller;

import com.core.auth.constants.ApiPaths;
import com.core.auth.dto.request.AuthRequest;
import com.core.auth.dto.request.RegisterRequest;
import com.core.auth.dto.request.TokenRefreshRequest;
import com.core.auth.dto.response.ApiResponse;
import com.core.auth.dto.response.AuthResponse;
import com.core.auth.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping(ApiPaths.AUTH)
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Authentication endpoints")
public class AuthController {
    
    private final AuthService authService;
    
    @PostMapping(ApiPaths.REGISTER)
    @Operation(summary = "User registration")
    public Mono<ApiResponse<AuthResponse>> register(@Valid @RequestBody RegisterRequest request) {
        return authService.register(request)
                .map(response -> ApiResponse.success("Registration successful", response));
    }

    @PostMapping(ApiPaths.LOGIN)
    @Operation(summary = "User login")
    public Mono<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody AuthRequest request,
            ServerHttpRequest serverRequest) {
        
        String ipAddress = extractIpAddress(serverRequest);
        String userAgent = serverRequest.getHeaders().getFirst(HttpHeaders.USER_AGENT);
        
        return authService.login(request, ipAddress, userAgent)
                .map(response -> ApiResponse.success("Login successful", response));
    }
    
    @PostMapping(ApiPaths.REFRESH)
    @Operation(summary = "Refresh access token")
    public Mono<ApiResponse<AuthResponse>> refreshToken(
            @Valid @RequestBody TokenRefreshRequest request,
            ServerHttpRequest serverRequest) {
        
        String ipAddress = extractIpAddress(serverRequest);
        String userAgent = serverRequest.getHeaders().getFirst(HttpHeaders.USER_AGENT);
        
        return authService.refreshToken(request.getRefreshToken(), ipAddress, userAgent)
                .map(response -> ApiResponse.success("Token refreshed successfully", response));
    }
    
    @PostMapping(ApiPaths.LOGOUT)
    @PreAuthorize("isAuthenticated()")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "User logout")
    public Mono<ApiResponse<Void>> logout(
            @RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader,
            @RequestParam String userId,
            ServerHttpRequest serverRequest) {
        
        String token = authHeader.substring(7); // Remove "Bearer " prefix
        String ipAddress = extractIpAddress(serverRequest);
        
        return authService.logout(token, userId, ipAddress)
                .thenReturn(ApiResponse.success("Logout successful", null));
    }
    
    private String extractIpAddress(ServerHttpRequest request) {
        String xForwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddress() != null ? 
            request.getRemoteAddress().getAddress().getHostAddress() : "unknown";
    }
}