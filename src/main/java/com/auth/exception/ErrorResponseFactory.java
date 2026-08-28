package com.auth.exception;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class ErrorResponseFactory {

    public ErrorResponse create(HttpStatus status, String error, Object message) {
        return new ErrorResponse(status.value(), error, message, LocalDateTime.now());
    }
}
