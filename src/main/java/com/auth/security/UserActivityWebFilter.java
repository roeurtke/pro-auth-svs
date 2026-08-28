package com.auth.security;

import com.auth.model.User;
import com.auth.service.UserActivityService;
import com.auth.util.AuditUtil;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * @author Roeurt Kesei
 * Web filter for recording user activity and audit events for each API request.
 */
@Component
public class UserActivityWebFilter implements WebFilter {

    private final UserActivityService activityService;

    public UserActivityWebFilter(UserActivityService activityService) {
        this.activityService = activityService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return chain.filter(exchange)
            .then(Mono.defer(() -> AuditUtil.getCurrentUser()
                .flatMap(user -> recordRequest(exchange, user))
                .switchIfEmpty(recordRequest(exchange, null))))
            .onErrorResume(error -> recordRequestForCurrentUser(exchange)
                .then(Mono.error(error)));
    }

    private Mono<Void> recordRequestForCurrentUser(ServerWebExchange exchange) {
        return AuditUtil.getCurrentUser()
            .flatMap(user -> recordRequest(exchange, user))
            .switchIfEmpty(recordRequest(exchange, null));
    }

    private Mono<Void> recordRequest(ServerWebExchange exchange, User user) {
        ServerHttpRequest request = exchange.getRequest();
        String forwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
        String ipAddress = forwardedFor != null ? forwardedFor.split(",", 2)[0].trim()
            : request.getRemoteAddress() == null ? null : request.getRemoteAddress().getAddress().getHostAddress();
        return activityService.record(com.auth.model.UserActivity.builder()
            .userId(user == null ? null : user.getId())
            .username(user == null ? null : user.getUsername())
            .eventType("API_REQUEST")
            .requestMethod(request.getMethod().name())
            .requestPath(request.getPath().value())
            .ipAddress(ipAddress)
            .userAgent(request.getHeaders().getFirst("User-Agent"))
            .successful(exchange.getResponse().getStatusCode() == null ||
                exchange.getResponse().getStatusCode().is2xxSuccessful())
            .build())
            .then(user == null ? Mono.empty() : activityService.updateLastActive(user.getId()));
    }
}