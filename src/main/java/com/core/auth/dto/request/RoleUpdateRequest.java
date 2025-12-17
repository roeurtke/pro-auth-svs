package com.core.auth.dto.request;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.util.HashSet;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleUpdateRequest {
    
    @Size(min = 2, max = 50, message = "Role name must be between 2 and 50 characters")
    private String name;
    
    @Size(min = 2, max = 20, message = "Role code must be between 2 and 20 characters")
    private String code;
    
    @Size(max = 500, message = "Description must be less than 500 characters")
    private String description;
    
    private Boolean systemRole;
    
    @Builder.Default
    private Set<Long> permissionIds = new HashSet<>();
    
    // Custom validation methods
    
    @AssertTrue(message = "System role cannot be modified to non-system")
    public boolean isValidSystemRoleUpdate() {
        // If systemRole is being set to false, it's invalid
        if (systemRole != null && systemRole == false) {
            return false;
        }
        return true;
    }
    
    @AssertTrue(message = "Role code cannot be changed for system roles")
    public boolean isValidCodeUpdate() {
        // If code is being changed and role is system role, it's invalid
        if (code != null && systemRole != null && systemRole) {
            return false;
        }
        return true;
    }
}