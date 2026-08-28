package com.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * @author Roeurt Kesei
 * DTO for permission creation requests.
 */
@Schema(description = "Permission creation request")
public class PermissionCreateRequest {
    @NotBlank(message = "Permission name is required")
    @Size(min = 2, max = 100, message = "Permission name must be between 2 and 100 characters")
    @Schema(description = "Permission name", example = "USER_READ")
    private String name;

    @Schema(description = "Permission description", example = "Read user data")
    private String description;

    @Schema(description = "Permission status code")
    private Integer status;

    @Schema(description = "Whether the permission is soft deleted")
    private Boolean isDeleted;
    
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getDescription() {
        return description;
    }
    
    public void setDescription(String description) {
        this.description = description;
    }
    
    public Integer getStatus() {
        return status;
    }
    
    public void setStatus(Integer status) {
        this.status = status;
    }
    
    public Boolean getIsDeleted() {
        return isDeleted;
    }
    
    public void setIsDeleted(Boolean isDeleted) {
        this.isDeleted = isDeleted;
    }
}

