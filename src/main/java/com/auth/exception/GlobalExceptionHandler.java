package com.auth.exception;

import io.jsonwebtoken.ExpiredJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Roeurt Kesei
 * Global exception handler to manage and format error responses consistently
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private final ErrorResponseFactory errorResponseFactory;

    public GlobalExceptionHandler(ErrorResponseFactory errorResponseFactory) {
        this.errorResponseFactory = errorResponseFactory;
    }

    @ExceptionHandler(WebExchangeBindException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleValidationExceptions(WebExchangeBindException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->
            errors.put(error.getField(), error.getDefaultMessage()));

        return Mono.just(buildErrorResponse(
            HttpStatus.BAD_REQUEST,
            "Validation Error",
            errors
        ));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleIllegalArgumentException(IllegalArgumentException ex) {
        return Mono.just(buildErrorResponse(
            HttpStatus.BAD_REQUEST,
            "Invalid Input",
            ex.getMessage()
        ));
    }

    @ExceptionHandler(ExpiredJwtException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleExpiredJwtException(ExpiredJwtException ex) {
        return Mono.just(buildErrorResponse(
            HttpStatus.UNAUTHORIZED,
            "Token Expired",
            "Your access token has expired. Please refresh your token."
        ));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public Mono<ResponseEntity<ErrorResponse>> handleAccessDeniedException(AccessDeniedException ex) {
        String message = ex.getMessage() != null && !"Access Denied".equalsIgnoreCase(ex.getMessage())
            ? ex.getMessage()
            : "You don't have permission to access this resource.";

        ErrorResponse response = errorResponseFactory.create(
            HttpStatus.FORBIDDEN,
            "Forbidden",
            message
        );

        return Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).body(response));
    }

    @ExceptionHandler(RuntimeException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleRuntimeException(RuntimeException ex) {
        String message = ex.getMessage() != null ? ex.getMessage() : "Request processing failed";

        HttpStatus status = isTokenException(message)
            ? HttpStatus.UNAUTHORIZED
            : HttpStatus.BAD_REQUEST;

        return Mono.just(buildErrorResponse(
            status,
            status == HttpStatus.UNAUTHORIZED ? "Token Error" : "Bad Request",
            message
        ));
    }

    @ExceptionHandler(Exception.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleGenericException(Exception ex) {
        logger.error("Unhandled exception", ex);
        return Mono.just(buildErrorResponse(
            HttpStatus.INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "An unexpected error occurred"
        ));
    }

    @ExceptionHandler(DeletedExceptionHandler.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleDeletedException(DeletedExceptionHandler ex) {
        return Mono.just(buildErrorResponse(
            HttpStatus.BAD_REQUEST,
            "Resource Deleted",
            ex.getMessage()
        ));
    }

    private ResponseEntity<Map<String, Object>> buildErrorResponse(HttpStatus status, String error, Object message) {
        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", status.value());
        response.put("error", error);
        response.put("message", message);
        return ResponseEntity.status(status).body(response);
    }

    private boolean isTokenException(String message) {
        return message != null && (message.toLowerCase().contains("token") || message.toLowerCase().contains("jwt"));
    }
}