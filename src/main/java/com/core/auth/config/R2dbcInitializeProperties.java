package com.core.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "spring.r2dbc.initialize")
public class R2dbcInitializeProperties {

    /**
     * Whether R2DBC nitialize is enabled.
     */
    private boolean enabled = true;

    /**
     * Initialize mode (e.g. always, never).
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
