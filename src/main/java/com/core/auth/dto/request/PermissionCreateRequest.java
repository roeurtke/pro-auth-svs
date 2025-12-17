package com.core.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class PermissionCreateRequest {
    
    @NotBlank(message = "Permission name is required")
    @Size(min = 2, max = 100, message = "Permission name must be between 2 and 100 characters")
    private String name;
    
    @NotBlank(message = "Permission code is required")
    @Size(min = 2, max = 50, message = "Permission code must be between 2 and 50 characters")
    private String code;
    
    private String description;
    private String category;
}