package com.core.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "spring.r2dbc.initialization")
public class R2dbcInitializationProperties {

    /**
     * Whether R2DBC initialization is enabled.
     */
    private boolean enabled = true;

    /**
     * Initialization mode (e.g. always, never).
     */
    private String mode = "always";

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }
}
