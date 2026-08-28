package com.auth.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * @author Roeurt Kesei
 * DTO for changing a user's password.
 */
@Schema(description = "User password change request")
public class UserPasswordChangeRequest {

    @NotBlank(message = "New password is required")
    @Schema(description = "New password", example = "newPassword123")
    private String newPassword;

    @NotBlank(message = "Confirm new password is required")
    @Schema(description = "Confirmation of the new password", example = "newPassword123")
    private String confirmNewPassword;

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getConfirmNewPassword() {
        return confirmNewPassword;
    }

    public void setConfirmNewPassword(String confirmNewPassword) {
        this.confirmNewPassword = confirmNewPassword;
    }
}