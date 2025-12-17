package com.core.auth.exception;

public class UserNotFoundException extends AuthException {
    
    public UserNotFoundException(Long userId) {
        super("User not found with id: " + userId, "USER_NOT_FOUND");
    }
    
    public UserNotFoundException(String username) {
        super("User not found with username: " + username, "USER_NOT_FOUND");
    }
}