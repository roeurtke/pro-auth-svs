package com.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * @author Roeurt Kesei
 * Simple DTO for registration responses.
 */
@Schema(description = "Registration response")
public class RegisterResponse {

    @Schema(description = "Response message", example = "User registered successful.")
    private String message;

    public RegisterResponse() {}

    public RegisterResponse(String message) {
        this.message = message;
    }

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
}
