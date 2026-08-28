package com.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.LocalDateTime;

/**
 * @author Roeurt Kesei
 * Holds error response DTO structure.
 */
@Schema(description = "Error response structure")
public class ErrorResponse {
    
    @Schema(description = "Timestamp when error occurred")
    private LocalDateTime timestamp;
    
    @Schema(description = "HTTP status code")
    private int status;
    
    @Schema(description = "Error type")
    private String error;
    
    @Schema(description = "Error message")
    private String message;
    
    @Schema(description = "Request path")
    private String path;

    public ErrorResponse() {
        this.timestamp = LocalDateTime.now();
    }

    public ErrorResponse(int status, String error, String message) {
        this();
        this.status = status;
        this.error = error;
        this.message = message;
    }

    // Getters and Setters
    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    
    public int getStatus() { return status; }
    public void setStatus(int status) { this.status = status; }
    
    public String getError() { return error; }
    public void setError(String error) { this.error = error; }
    
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    
    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }
}