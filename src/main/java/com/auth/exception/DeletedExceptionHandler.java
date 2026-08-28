package com.auth.exception;

/**
 * @author Roeurt Kesei
 * Exception thrown when an entity is soft-deleted but accessed.
 */
public class DeletedExceptionHandler extends RuntimeException {
    public DeletedExceptionHandler() {
        super("This resource has been deleted.");
    }

    public DeletedExceptionHandler(String message) {
        super(message);
    }

    public DeletedExceptionHandler(Long id) {
        super("Resource with id " + id + " has been deleted.");
    }
}
