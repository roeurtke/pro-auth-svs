package com.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.LocalDateTime;
import java.util.List;

/**
 * @author Roeurt Kesei
 * DTO for user responses.
 */
@Schema(description = "User data transfer object")
public class UserResponse {
    
    @Schema(description = "User ID", example = "1")
    private Long id;
    
    @Schema(description = "First name", example = "John")
    private String firstName;
    
    @Schema(description = "Last name", example = "Doe")
    private String lastName;
    
    @Schema(description = "Username", example = "john_doe")
    private String username;
    
    @Schema(description = "Email address", example = "john.doe@example.com")
    private String email;
    
    @Schema(description = "Phone number", example = "+1234567890")
    private String phoneNumber;
    
    @Schema(description = "User status code (Enum code)", example = "1001")
    private String status;
    
    @Schema(description = "Whether user is deleted", example = "false")
    private Boolean isDeleted;
    
    @Schema(description = "User roles")
    private List<Long> roles;
    
    @Schema(description = "Creation timestamp")
    private LocalDateTime publishedAt;
    
    @Schema(description = "Last update timestamp")
    private LocalDateTime modifiedAt;

    @Schema(description = "User created by user ID")
    private Long publishedId;

    @Schema(description = "User last updated by user ID")
    private Long modifiedId;

    public UserResponse() {}

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getFirstName() { return firstName; }
    public void setFirstName(String firstName) { this.firstName = firstName; }
    
    public String getLastName() { return lastName; }
    public void setLastName(String lastName) { this.lastName = lastName; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public String getPhoneNumber() { return phoneNumber; }
    public void setPhoneNumber(String phoneNumber) { this.phoneNumber = phoneNumber; }
    
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    
    public Boolean getIsDeleted() { return isDeleted; }
    public void setIsDeleted(Boolean isDeleted) { this.isDeleted = isDeleted; }
    
    public List<Long> getRoles() { return roles; }
    public void setRoles(List<Long> roles) { this.roles = roles; }

    public LocalDateTime getPublishedAt() { return publishedAt; }
    public void setPublishedAt(LocalDateTime publishedAt) { this.publishedAt = publishedAt; }

    public LocalDateTime getModifiedAt() { return modifiedAt; }
    public void setModifiedAt(LocalDateTime modifiedAt) { this.modifiedAt = modifiedAt; }

    public Long getPublishedId() { return publishedId; }
    public void setPublishedId(Long publishedId) { this.publishedId = publishedId; }

    public Long getModifiedId() { return modifiedId; }
    public void setModifiedId(Long modifiedId) { this.modifiedId = modifiedId; }
}