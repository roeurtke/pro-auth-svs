package com.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * @author Roeurt Kesei
 * DTO for authentication requests containing username and password.
 */
@Schema(description = "Authentication request")
public class AuthRequest {
    
    @NotBlank(message = "Username is required")
    @Schema(description = "Username", example = "john_doe")
    private String username;
    
    @NotBlank(message = "Password is required")
    @Schema(description = "Password", example = "password123")
    private String password;

    public AuthRequest() {}
    
    public AuthRequest(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}