package com.auth.model;

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
@Table("tbl_user_activity")
public class UserActivity {

    @Id
    private Long id;
    private Long userId;
    private Long targetUserId;
    private String username;
    private String eventType;
    private String requestMethod;
    private String requestPath;
    private String ipAddress;
    private String userAgent;
    private Boolean successful;
    private String details;
    private LocalDateTime createdAt;
}