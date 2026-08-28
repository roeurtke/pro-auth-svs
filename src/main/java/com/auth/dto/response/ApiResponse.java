package com.auth.dto.response;

/**
 * @author Roeurt Kesei
 * Generic API response wrapper.
 * @param <T> response payload type
 */
public class ApiResponse<T> {
    private String message;
    private T data;

    public ApiResponse() {}

    public ApiResponse(String message, T data) {
        this.message = message;
        this.data = data;
    }

    public static <T> ApiResponse<T> success(String message, T data) {
        return new ApiResponse<>(message, data);
    }

    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>("Request completed successfully.", data);
    }

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }

    public T getData() { return data; }
    public void setData(T data) { this.data = data; }
}
