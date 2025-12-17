package com.core.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("tbl_api_client")
public class ApiClient {
    
    @Id
    private Long id;
    
    private String clientId;
    private String clientSecret;
    private String name;
    private String description;
    private String[] scopes;
    private String[] redirectUris;
    private String[] grantTypes;
    
    private LocalDateTime createdAt;
    private LocalDateTime expiresAt;
    
    @Builder.Default
    private boolean active = true;
    @Builder.Default
    private boolean confidential = true;
    
    public boolean isValid() {
        return active && (expiresAt == null || expiresAt.isAfter(LocalDateTime.now()));
    }
}