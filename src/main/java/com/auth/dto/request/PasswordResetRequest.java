package com.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * @author Roeurt Kesei
 * Request to send a password reset verification code
 */
@Schema(description = "Request to send a password reset verification code")
public class PasswordResetRequest {

    @Email(message = "Email should be valid")
    @NotBlank(message = "Email is required")
    @Schema(description = "User email address", example = "john.doe@example.com")
    private String email;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}