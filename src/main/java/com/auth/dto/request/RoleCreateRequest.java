package com.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.Set;

/**
 * @author Roeurt Kesei
 * DTO for role creation requests.
 */
@Schema(description = "Role creation request")
public class RoleCreateRequest {
    @NotBlank(message = "Role name is required")
    @Size(min = 2, max = 100, message = "Role name must be between 2 and 100 characters")
    @Schema(description = "Role name", example = "ADMIN")
    private String name;

    @Schema(description = "Role description", example = "Administrator with full access")
    private String description;

    @Schema(description = "Role status code")
    private Integer status;

    @Schema(description = "Whether the role is soft deleted")
    private Boolean isDeleted;

    @Schema(description = "Permissions assigned to the role")
    private Set<PermissionRequest> permissions;
    
    // Nested DTO for permissions in request
    public static class PermissionRequest {
        private Long id;
        private String name;
        private String description;
        
        public Long getId() {
            return id;
        }
        
        public void setId(Long id) {
            this.id = id;
        }
        
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
    }
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
    public Set<PermissionRequest> getPermissions() {
        return permissions;
    }
    public void setPermissions(Set<PermissionRequest> permissions) {
        this.permissions = permissions;
    }    
}
