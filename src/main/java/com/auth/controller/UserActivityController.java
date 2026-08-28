package com.auth.controller;

import com.auth.dto.response.UserActivityResponse;
import com.auth.dto.response.PageResponse;
import com.auth.service.UserActivityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * @author Roeurt Kesei
 * Controller for handling user activity and audit events.
 */
@RestController
@RequestMapping("${api.base}/user_mod/activity")
@Tag(name = "User Activity", description = "Authentication, audit, and usage activity")
@SecurityRequirement(name = "bearerAuth")
public class UserActivityController {

    private final UserActivityService activityService;

    public UserActivityController(UserActivityService activityService) {
        this.activityService = activityService;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('USER_READ')")
    @Operation(summary = "Get user activity", description = "Retrieve paginated activity and audit events")
    public Mono<PageResponse<UserActivityResponse>> getActivity(
        @RequestParam(required = false) Long userId,
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "25") int size
    ) {
        int boundedSize = Math.min(Math.max(size, 1), 100);
        long offset = (long) Math.max(page, 0) * boundedSize;
        return activityService.findRecent(userId, boundedSize, offset)
            .map(UserActivityResponse::from)
            .collectList()
            .zipWith(activityService.count(userId))
            .map(result -> new PageResponse<>(result.getT1(), Math.max(page, 0), boundedSize, result.getT2()));
    }
}