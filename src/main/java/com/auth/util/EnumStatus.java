package com.auth.util;

/**
 * @author Roeurt Kesei
 * Enum representing the status of a user.
 */
public enum EnumStatus {

    DELETED("0001", "Deleted"),
    ACTIVATED("1001", "Activated"),
    DEACTIVATED("2001", "Deactivated");

    private final String value;
    private final String displayName;

    EnumStatus(String value, String displayName) {
        this.value = value;
        this.displayName = displayName;
    }

    public String getValue() {
        return value;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static EnumStatus fromValue(String value) {
        for (EnumStatus status : values()) {
            if (status.value.equals(value)) {
                return status;
            }
        }
        throw new IllegalArgumentException("Invalid status value: " + value);
    }
}
