package com.example.secure.access;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * Backs every hasPermission(...) expression.
 *   hasPermission('Order','read')           -> does the user hold "order:read"?
 *   hasPermission(#id,'Order','update')     -> holds "order:update" AND the Order policy allows this id.
 * Deny by default.
 */
@Component
public class AppPermissionEvaluator implements PermissionEvaluator {

    private final Map<String, ResourcePolicy> policies;

    public AppPermissionEvaluator(List<ResourcePolicy> policies) {
        this.policies = policies.stream().collect(Collectors.toUnmodifiableMap(ResourcePolicy::type, Function.identity()));
    }

    @Override
    public boolean hasPermission(Authentication auth, Object type, Object action) {
        return type instanceof String t && action instanceof String a && Grants.has(auth, Grants.name(t, a));
    }

    @Override
    public boolean hasPermission(Authentication auth, Serializable id, String type, Object action) {
        return action instanceof String a
            && Grants.has(auth, Grants.name(type, a))                       // cheap check first
            && Optional.ofNullable(policies.get(type))
                       .map(policy -> policy.canAccess(auth, id, a))
                       .orElse(false);                                        // no policy => deny
    }
}
