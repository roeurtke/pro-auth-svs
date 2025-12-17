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
@Table("tbl_session")
public class Session {
    
    @Id
    private Long id;
    
    private String userId;
    private String sessionToken;
    private String ipAddress;
    private String userAgent;
    private String deviceInfo;
    private String location;
    
    private LocalDateTime loginAt;
    private LocalDateTime lastActivityAt;
    private LocalDateTime logoutAt;
    private LocalDateTime expiresAt;
    
    private boolean active;
    private String logoutReason;
    
    public boolean isValid() {
        return active && expiresAt.isAfter(LocalDateTime.now());
    }
}