package com.core.auth.dto.request;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PermissionUpdateRequest {
    
    @Size(min = 2, max = 100, message = "Permission name must be between 2 and 100 characters")
    private String name;
    
    @Size(min = 2, max = 50, message = "Permission code must be between 2 and 50 characters")
    @Pattern(
        regexp = "^[A-Z_]+$",
        message = "Permission code must contain only uppercase letters and underscores"
    )
    private String code;
    
    @Size(max = 500, message = "Description must be less than 500 characters")
    private String description;
    
    @Size(max = 50, message = "Category must be less than 50 characters")
    @Pattern(
        regexp = "^[A-Z_]+$",
        message = "Category must contain only uppercase letters and underscores"
    )
    private String category;
    
    // Validation groups
    public interface BasicUpdate {}
    public interface FullUpdate {}
    
    @AssertTrue(groups = BasicUpdate.class, message = "Cannot change permission code in basic update")
    public boolean isValidBasicUpdate() {
        return code == null;
    }
    
    // Helper method to check if update is partial
    public boolean isPartialUpdate() {
        return name == null && code == null && description == null && category == null;
    }
}