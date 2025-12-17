package com.core.auth.exception;

public class SessionNotFoundException extends RuntimeException {
    
    public SessionNotFoundException(String sessionToken) {
        super("Session not found with token: " + sessionToken);
    }
    
    public SessionNotFoundException(Long sessionId) {
        super("Session not found with ID: " + sessionId);
    }
}