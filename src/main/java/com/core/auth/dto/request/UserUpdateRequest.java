package com.core.auth.dto.request;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserUpdateRequest {
    
    @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
    private String firstName;
    
    @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
    private String lastName;
    
    @Email(message = "Email should be valid")
    @Size(max = 100, message = "Email must be less than 100 characters")
    private String email;
    
    @Pattern(
        regexp = "^\\+?[1-9]\\d{1,14}$",
        message = "Phone number must be a valid international format"
    )
    private String phone;
    
    private Boolean enabled;
    
    private Boolean locked;
    
    private Boolean mfaEnabled;
    
    @Size(max = 255, message = "MFA secret must be less than 255 characters")
    private String mfaSecret;
    
    private Set<Long> roleIds;
    
    // Validation groups for different scenarios
    public interface BasicUpdate {}
    public interface AdminUpdate {}
    
    @AssertTrue(groups = AdminUpdate.class, message = "Cannot lock and disable user simultaneously")
    public boolean isValidStatus() {
        if (enabled != null && locked != null) {
            return !(enabled == false && locked == true);
        }
        return true;
    }
    
    @AssertTrue(groups = BasicUpdate.class, message = "Cannot change sensitive fields")
    public boolean isBasicUpdateValid() {
        // For basic updates, users shouldn't be able to change enabled/locked status or roles
        return enabled == null && locked == null && mfaEnabled == null && 
            mfaSecret == null && (roleIds == null || roleIds.isEmpty());
    }
}