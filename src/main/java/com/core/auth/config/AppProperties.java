package com.core.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author Kesei Roeurt
 * Centralized application properties.
 */
public class AppProperties {

    /**
     * Argon2 password hashing properties.
     */
    @ConfigurationProperties(prefix = "security.password.argon2")
    public static class Argon2 {
        private int iterations;
        private int memory;
        private int parallelism;
        private int saltLength;
        private int hashLength;

        public int getIterations() {
            return iterations;
        }
        public void setIterations(int iterations) {
            this.iterations = iterations;
        }

        public int getMemory() {
            return memory;
        }
        public void setMemory(int memory) {
            this.memory = memory;
        }

        public int getParallelism() {
            return parallelism;
        }
        public void setParallelism(int parallelism) {
            this.parallelism = parallelism;
        }

        public int getSaltLength() {
            return saltLength;
        }
        public void setSaltLength(int saltLength) {
            this.saltLength = saltLength;
        }

        public int getHashLength() {
            return hashLength;
        }
        public void setHashLength(int hashLength) {
            this.hashLength = hashLength;
        }
    }

    /**
     * Database initialization and cleanup properties.
     */
    @ConfigurationProperties(prefix = "app.db")
    public static class Database {
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

    /**
     * Multi-factor authentication properties.
     */
    @ConfigurationProperties(prefix = "mfa")
    public static class Mfa {
        private String issuer;
        private QrCode qrCode = new QrCode();

        public String getIssuer() {
            return issuer;
        }
        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public QrCode getQrCode() {
            return qrCode;
        }
        public void setQrCode(QrCode qrCode) {
            this.qrCode = qrCode;
        }

        public static class QrCode {
            private int size;

            public int getSize() {
                return size;
            }
            public void setSize(int size) {
                this.size = size;
            }
        }
    }

    /**
     * R2DBC initialization properties.
     */
    @ConfigurationProperties(prefix = "spring.r2dbc.initialization")
    public static class R2dbcInitialization {
        private boolean enabled = true;
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
}
