package com.example.secure.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/** Typed, validated-by-construction settings under app.security.*. */
@ConfigurationProperties("app.security")
public record SecurityProps(
        @DefaultValue("3") int maxSessions,
        @DefaultValue Lockout lockout,
        @DefaultValue Bootstrap bootstrap) {

    public record Lockout(
            @DefaultValue("5") int maxAttempts,
            @DefaultValue("1m") Duration baseDuration,
            @DefaultValue("1h") Duration maxDuration) {}

    public record Bootstrap(@DefaultValue("admin") String adminUsername, String adminPassword) {}
}
