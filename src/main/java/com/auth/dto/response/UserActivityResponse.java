package com.auth.dto.response;

import com.auth.model.UserActivity;
import io.swagger.v3.oas.annotations.media.Schema;

import java.time.LocalDateTime;

/**
 * @author Roeurt Kesei
 * DTO for user activity responses.
 */
@Schema(description = "User activity and audit event")
public record UserActivityResponse(
    Long id,
    Long userId,
    Long targetUserId,
    String username,
    String eventType,
    String requestMethod,
    String requestPath,
    String ipAddress,
    String userAgent,
    Boolean successful,
    String details,
    LocalDateTime createdAt
) {
    public static UserActivityResponse from(UserActivity activity) {
        return new UserActivityResponse(activity.getId(), activity.getUserId(), activity.getTargetUserId(),
            activity.getUsername(), activity.getEventType(), activity.getRequestMethod(), activity.getRequestPath(),
            activity.getIpAddress(), activity.getUserAgent(), activity.getSuccessful(), activity.getDetails(),
            activity.getCreatedAt());
    }
}