package com.yakbas.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = ApplicationProperties.CONFIG_PROPERTIES_PREF)
public class ApplicationProperties {
    public static final String CONFIG_PROPERTIES_PREF = "application";

    private String secret;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }
}
