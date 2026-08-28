package com.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.time.Duration;

/**
 * @author Roeurt Kesei
 * Centralized application properties.
 */
public class AppProperties {
    
    /**
     * API related properties.
     * api.*
     */
    @ConfigurationProperties(prefix = "api")
    public static class Api {
        private String base;

        public String getBase() {
            return base;
        }

        public void setBase(String base) {
            this.base = base;
        }
    }
    
    /**
     * Database initialization and cleanup properties.
     * app.db.*
     */
    @ConfigurationProperties(prefix = "app.db")
    public static class Database {
        private boolean init;
        private Cleanup cleanup = new Cleanup();

        public boolean isInit() { return init; }
        public void setInit(boolean init) { this.init = init; }

        public Cleanup getCleanup() { return cleanup; }
        public void setCleanup(Cleanup cleanup) { this.cleanup = cleanup; }

        public static class Cleanup {
            private boolean enabled;

            public boolean isEnabled() { return enabled; }
            public void setEnabled(boolean enabled) { this.enabled = enabled; }
        }
    }

    /**
     * Password reset properties.
     * app.password-reset.*
     */
    @ConfigurationProperties(prefix = "app.password-reset")
    public static class PasswordReset {
        /**
         * How long a generated verification code stays valid.
         * Accepts simple duration strings, e.g. "10m", "30s", "1h".
         */
        private Duration codeLifetime = Duration.ofMinutes(10);

        public Duration getCodeLifetime() { return codeLifetime; }
        public void setCodeLifetime(Duration codeLifetime) { this.codeLifetime = codeLifetime; }
    }

    /**
     * R2DBC properties (initialization + mapping).
     * spring.r2dbc.*
     */
    @ConfigurationProperties(prefix = "spring.r2dbc")
    public static class R2dbc {
        private Initialization initialization = new Initialization();
        private Mapping mapping = new Mapping();

        public Initialization getInitialization() { return initialization; }
        public void setInitialization(Initialization initialization) { this.initialization = initialization; }

        public Mapping getMapping() { return mapping; }
        public void setMapping(Mapping mapping) { this.mapping = mapping; }

        /**
         * spring.r2dbc.initialization.*
         */
        public static class Initialization {
            private boolean enabled = true;
            private String mode = "always";

            public boolean isEnabled() { return enabled; }
            public void setEnabled(boolean enabled) { this.enabled = enabled; }

            public String getMode() { return mode; }
            public void setMode(String mode) { this.mode = mode; }
        }

        /**
         * spring.r2dbc.mapping.*
         */
        public static class Mapping {
            private String namingStrategy = "SNAKE_CASE";

            public String getNamingStrategy() { return namingStrategy; }
            public void setNamingStrategy(String namingStrategy) { this.namingStrategy = namingStrategy; }
        }
    }
}