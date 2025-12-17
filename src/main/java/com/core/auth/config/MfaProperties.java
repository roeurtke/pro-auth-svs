package com.core.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "mfa")
public class MfaProperties {
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
