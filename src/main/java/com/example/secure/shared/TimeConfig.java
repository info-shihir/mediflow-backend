package com.example.secure.shared;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class TimeConfig {
    /** Injected everywhere instead of Instant.now(), so time-dependent rules are testable. */
    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
