package com.core.auth.config;

import com.core.auth.exception.*;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import org.springframework.web.server.ServerWebInputException;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(AuthException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleAuthException(AuthException ex) {
        return createErrorResponse(HttpStatus.UNAUTHORIZED, ex.getMessage(), "AUTH_ERROR");
    }
    
    @ExceptionHandler(TokenException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleTokenException(TokenException ex) {
        return createErrorResponse(HttpStatus.UNAUTHORIZED, ex.getMessage(), "TOKEN_ERROR");
    }
    
    @ExceptionHandler(UserNotFoundException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleUserNotFoundException(UserNotFoundException ex) {
        return createErrorResponse(HttpStatus.NOT_FOUND, ex.getMessage(), "USER_NOT_FOUND");
    }
    
    @ExceptionHandler(DeletedException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleDeletedException(DeletedException ex) {
        return createErrorResponse(HttpStatus.GONE, ex.getMessage(), "RESOURCE_DELETED");
    }
    
    @ExceptionHandler(BadCredentialsException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleBadCredentialsException(BadCredentialsException ex) {
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Invalid credentials", "BAD_CREDENTIALS");
    }
    
    @ExceptionHandler(AccessDeniedException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleAccessDeniedException(AccessDeniedException ex) {
        return createErrorResponse(HttpStatus.FORBIDDEN, "Access denied", "ACCESS_DENIED");
    }
    
    @ExceptionHandler(ExpiredJwtException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleExpiredJwtException(ExpiredJwtException ex) {
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Token has expired", "TOKEN_EXPIRED");
    }
    
    @ExceptionHandler(SignatureException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleSignatureException(SignatureException ex) {
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Invalid token signature", "INVALID_SIGNATURE");
    }
    
    @ExceptionHandler(WebExchangeBindException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleValidationException(WebExchangeBindException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getFieldErrors().forEach(error -> 
            errors.put(error.getField(), error.getDefaultMessage())
        );
        return createErrorResponse(HttpStatus.BAD_REQUEST, "Validation failed", "VALIDATION_ERROR", errors);
    }
    
    @ExceptionHandler(ServerWebInputException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleServerWebInputException(ServerWebInputException ex) {
        return createErrorResponse(HttpStatus.BAD_REQUEST, ex.getReason(), "INPUT_ERROR");
    }
    
    @ExceptionHandler(Exception.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleGenericException(Exception ex) {
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred", "INTERNAL_ERROR");
    }
    
    private Mono<ResponseEntity<Map<String, Object>>> createErrorResponse(
            HttpStatus status, String message, String errorCode) {
        return createErrorResponse(status, message, errorCode, null);
    }
    
    private Mono<ResponseEntity<Map<String, Object>>> createErrorResponse(
            HttpStatus status, String message, String errorCode, Map<String, String> details) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("status", status.value());
        errorResponse.put("error", status.getReasonPhrase());
        errorResponse.put("message", message);
        errorResponse.put("errorCode", errorCode);
        
        if (details != null && !details.isEmpty()) {
            errorResponse.put("details", details);
        }
        
        return Mono.just(ResponseEntity.status(status).body(errorResponse));
    }
}