package com.auth.security;

import com.auth.model.UserActivity;
import com.auth.service.UserActivityService;
import com.auth.util.AuditUtil;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Component
public class UserActivityWebFilter implements WebFilter {

    private final UserActivityService activityService;

    public UserActivityWebFilter(UserActivityService activityService) {
        this.activityService = activityService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        // 1. Skip paths that are manually audited or static noise
        if (shouldSkipAudit(path)) {
            return chain.filter(exchange);
        }

        // 2. Read context WHILE inside the Reactive Pipeline
        return AuditUtil.getCurrentUser()
            .flatMap(user -> chain.filter(exchange)
                .doOnSuccess(v -> logActivity(exchange, user.getId(), user.getUsername(), true))
                .doOnError(err -> logActivity(exchange, user.getId(), user.getUsername(), false)))
            .switchIfEmpty(Mono.defer(() -> chain.filter(exchange)
                .doOnSuccess(v -> logActivity(exchange, null, null, true))
                .doOnError(err -> logActivity(exchange, null, null, false))));
    }

    private void logActivity(ServerWebExchange exchange, Long userId, String username, boolean successful) {
        ServerHttpRequest request = exchange.getRequest();
        String forwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
        String ipAddress = forwardedFor != null ? forwardedFor.split(",", 2)[0].trim()
            : request.getRemoteAddress() == null ? null : request.getRemoteAddress().getAddress().getHostAddress();

        boolean is2xx = exchange.getResponse().getStatusCode() == null 
            || exchange.getResponse().getStatusCode().is2xxSuccessful();

        UserActivity activity = UserActivity.builder()
            .userId(userId)
            .username(username)
            .eventType("API_REQUEST")
            .requestMethod(request.getMethod().name())
            .requestPath(request.getPath().value())
            .ipAddress(ipAddress)
            .userAgent(request.getHeaders().getFirst("User-Agent"))
            .successful(successful && is2xx)
            .build();

        // Fire-and-forget save off-thread, carrying passed user variables
        activityService.record(activity)
            .then(userId == null ? Mono.empty() : activityService.updateLastActive(userId))
            .subscribe();
    }

    private boolean shouldSkipAudit(String path) {
        return path.contains("/auth_mod/login")      // Handled manually by Auth Controller (LOGIN_SUCCESS)
            || path.contains("/auth_mod/logout")     // Handled manually if needed
            || path.contains("/user_mod/activity")   // Avoid auditing the audit fetch itself
            || path.contains("/swagger") 
            || path.contains("/v3/api-docs") 
            || path.contains("/favicon.ico");
    }
}