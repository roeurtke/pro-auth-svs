package com.core.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.Set;

@Data
public class RoleCreateRequest {
    
    @NotBlank(message = "Role name is required")
    @Size(min = 2, max = 50, message = "Role name must be between 2 and 50 characters")
    private String name;
    
    @NotBlank(message = "Role code is required")
    @Size(min = 2, max = 20, message = "Role code must be between 2 and 20 characters")
    private String code;
    
    private String description;
    
    private Set<Long> permissionIds;
}