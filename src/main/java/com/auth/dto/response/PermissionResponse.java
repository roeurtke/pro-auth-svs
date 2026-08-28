package com.auth.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.LocalDateTime;

/**
 * @author Roeurt Kesei
 * DTO for permission responses.
 */
@Schema(description = "Permission data transfer object")
public class PermissionResponse {
    
    @Schema(description = "Permission ID", example = "1")
    private Long id;
    
    @Schema(description = "Permission name", example = "USER_READ")
    private String name;
    
    @Schema(description = "Permission description", example = "Read user information")
    private String description;
    
    @Schema(description = "Permission status code (Enum code)", example = "1001")
    private String status;
    
    @Schema(description = "Whether permission is deleted", example = "false")
    private Boolean isDeleted;
    
    @Schema(description = "Creation timestamp")
    private LocalDateTime publishedAt;
    
    @Schema(description = "Last update timestamp")
    private LocalDateTime modifiedAt;

    @Schema(description = "User created by user ID")
    private Long publishedId;

    @Schema(description = "User last updated by user ID")
    private Long modifiedId;

    public PermissionResponse() {}

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    
    public Boolean getIsDeleted() { return isDeleted; }
    public void setIsDeleted(Boolean isDeleted) { this.isDeleted = isDeleted; }
    
    public LocalDateTime getPublishedAt() { return publishedAt; }
    public void setPublishedAt(LocalDateTime publishedAt) { this.publishedAt = publishedAt; }

    public LocalDateTime getModifiedAt() { return modifiedAt; }
    public void setModifiedAt(LocalDateTime modifiedAt) { this.modifiedAt = modifiedAt; }

    public Long getPublishedId() { return publishedId; }
    public void setPublishedId(Long publishedId) { this.publishedId = publishedId; }

    public Long getModifiedId() { return modifiedId; }
    public void setModifiedId(Long modifiedId) { this.modifiedId = modifiedId; }
}

