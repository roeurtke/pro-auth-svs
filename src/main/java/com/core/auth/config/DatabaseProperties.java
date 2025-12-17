package com.core.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.db")
public class DatabaseProperties {
    private boolean init;
    private Cleanup cleanup = new Cleanup();

    public boolean isInit() {
        return init;
    }
    public void setInit(boolean init) {
        this.init = init;
    }

    public Cleanup getCleanup() {
        return cleanup;
    }
    public void setCleanup(Cleanup cleanup) {
        this.cleanup = cleanup;
    }

    public static class Cleanup {
        private boolean enabled;

        public boolean isEnabled() {
            return enabled;
        }
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }
}
