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
@Table("tbl_token")
public class Token {
    
    @Id
    private Long id;
    
    private String userId;
    private String token;
    private String tokenType; // ACCESS, REFRESH, RESET, VERIFICATION
    private boolean revoked;
    private boolean expired;
    
    private LocalDateTime createdAt;
    private LocalDateTime expiresAt;
    private LocalDateTime revokedAt;
    
    public boolean isValid() {
        return !revoked && !expired && expiresAt.isAfter(LocalDateTime.now());
    }
}