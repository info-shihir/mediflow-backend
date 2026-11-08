package com.example.secure.user;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.secure.config.SecurityProps;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class UserAccountLockoutTest {

    private static final SecurityProps.Lockout POLICY =
        new SecurityProps.Lockout(3, Duration.ofMinutes(1), Duration.ofMinutes(10));
    private final Instant now = Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void locksOnTheThirdFailureForTheBaseDuration() {
        var user = new UserAccount("Bob", "hash");
        user.registerFailure(POLICY, now);
        user.registerFailure(POLICY, now);
        assertThat(user.isLocked(now)).isFalse();

        user.registerFailure(POLICY, now);
        assertThat(user.isLocked(now)).isTrue();
        assertThat(user.isLocked(now.plus(Duration.ofMinutes(1)))).isFalse();
    }

    @Test
    void lockDoublesOnEachFurtherFailure() {
        var user = new UserAccount("bob", "hash");
        for (int i = 0; i < 4; i++) user.registerFailure(POLICY, now);   // 4th failure => 2 minutes
        assertThat(user.isLocked(now.plus(Duration.ofSeconds(119)))).isTrue();
        assertThat(user.isLocked(now.plus(Duration.ofMinutes(2)))).isFalse();
    }

    @Test
    void lockIsCapped() {
        var user = new UserAccount("bob", "hash");
        for (int i = 0; i < 40; i++) user.registerFailure(POLICY, now);
        assertThat(user.isLocked(now.plus(Duration.ofMinutes(9)))).isTrue();
        assertThat(user.isLocked(now.plus(Duration.ofMinutes(10)))).isFalse();
    }

    @Test
    void usernameIsNormalisedToLowerCase() {
        assertThat(new UserAccount("BoB", "hash").getUsername()).isEqualTo("bob");
    }
}
