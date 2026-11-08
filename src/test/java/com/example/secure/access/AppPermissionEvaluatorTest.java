package com.example.secure.access;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

class AppPermissionEvaluatorTest {

    private final Map<Long, String> owners = Map.of(1L, "alice");

    private final ResourcePolicy orderPolicy = new OwnedResourcePolicy() {
        @Override public String type() { return "Order"; }
        @Override protected Optional<String> ownerOf(Serializable id) { return Optional.ofNullable(owners.get(id)); }
    };

    private final AppPermissionEvaluator evaluator = new AppPermissionEvaluator(List.of(orderPolicy));

    private static Authentication user(String name, String... authorities) {
        return new TestingAuthenticationToken(name, "n/a", authorities);
    }

    @Test
    void typeLevel_needsTheAuthority() {
        assertThat(evaluator.hasPermission(user("bob", "order:read"), "Order", "read")).isTrue();
        assertThat(evaluator.hasPermission(user("bob", "order:read"), "Order", "delete")).isFalse();
        assertThat(evaluator.hasPermission(user("bob"), "Order", "read")).isFalse();
    }

    @Test
    void instanceLevel_ownerIsAllowed() {
        assertThat(evaluator.hasPermission(user("alice", "order:update"), 1L, "Order", "update")).isTrue();
    }

    @Test
    void instanceLevel_otherUserIsDenied() {
        assertThat(evaluator.hasPermission(user("bob", "order:update"), 1L, "Order", "update")).isFalse();
    }

    @Test
    void instanceLevel_ownerWithoutThePermissionIsDenied() {
        assertThat(evaluator.hasPermission(user("alice", "order:read"), 1L, "Order", "update")).isFalse();
    }

    @Test
    void instanceLevel_manageAllOverridesOwnership() {
        assertThat(evaluator.hasPermission(user("bob", "order:update", "order:manage-all"), 1L, "Order", "update")).isTrue();
    }

    @Test
    void instanceLevel_readAllOnlyCoversReads() {
        var bob = user("bob", "order:read", "order:update", "order:read-all");
        assertThat(evaluator.hasPermission(bob, 1L, "Order", "read")).isTrue();
        assertThat(evaluator.hasPermission(bob, 1L, "Order", "update")).isFalse();
    }

    @Test
    void unknownIdOrUnknownTypeIsDenied() {
        assertThat(evaluator.hasPermission(user("alice", "order:read"), 99L, "Order", "read")).isFalse();
        assertThat(evaluator.hasPermission(user("alice", "invoice:read"), 1L, "Invoice", "read")).isFalse();
    }
}
