package com.core.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
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
    
    @Column("user_id")
    private Long userId;  // Change from String to Long
    
    private String token;
    
    @Column("token_type")
    private String tokenType; // ACCESS, REFRESH, RESET, VERIFICATION
    
    private boolean revoked;
    private boolean expired;
    
    @Column("created_at")
    private LocalDateTime createdAt;
    
    @Column("expires_at")
    private LocalDateTime expiresAt;
    
    @Column("revoked_at")
    private LocalDateTime revokedAt;
    
    public boolean isValid() {
        return !revoked && !expired && expiresAt.isAfter(LocalDateTime.now());
    }
}