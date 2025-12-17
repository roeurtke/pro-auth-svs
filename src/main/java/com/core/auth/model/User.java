package com.core.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Transient;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("tbl_user")
public class User {
    
    @Id
    private Long id;
    
    private String username;
    private String email;
    private String password;
    private String firstName;
    private String lastName;
    private String phone;
    
    private boolean enabled;
    private boolean locked;
    private boolean mfaEnabled;
    private String mfaSecret;
    
    @CreatedDate
    private LocalDateTime createdAt;
    
    @LastModifiedDate
    private LocalDateTime updatedAt;
    
    private LocalDateTime lastLoginAt;
    private LocalDateTime passwordChangedAt;
    
    @Builder.Default
    private Integer failedLoginAttempts = 0;
    
    @Transient
    @Builder.Default
    private Set<Role> roles = new HashSet<>();
    
    @Transient
    @Builder.Default
    private Set<Permission> permissions = new HashSet<>();
    
    public String getFullName() {
        return firstName + " " + lastName;
    }
    
    public boolean isAccountNonExpired() {
        return true;
    }
    
    public boolean isAccountNonLocked() {
        return !locked;
    }
    
    public boolean isCredentialsNonExpired() {
        return true;
    }
}