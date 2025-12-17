package com.core.auth.exception;

public class TokenException extends AuthException {
    
    public TokenException(String message) {
        super(message, "TOKEN_ERROR");
    }
    
    public TokenException(String message, String errorCode) {
        super(message, errorCode);
    }
}