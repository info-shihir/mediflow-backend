package com.example.secure.auth;

import java.util.Set;
import java.util.TreeSet;
import org.springframework.security.core.Authentication;

/** What the UI is told. The UI only reads this to show/hide things; the backend still enforces everything. */
public record MeResponse(String username, Set<String> roles, Set<String> permissions, String token) {

    private static final String ROLE_PREFIX = "ROLE_";

    public MeResponse(String username, Set<String> roles, Set<String> permissions) {
        this(username, roles, permissions, null);
    }

    public static MeResponse from(Authentication auth) {
        Set<String> roles = new TreeSet<>();
        Set<String> permissions = new TreeSet<>();
        auth.getAuthorities().forEach(g -> {
            String a = g.getAuthority();
            if (a.startsWith(ROLE_PREFIX)) roles.add(a.substring(ROLE_PREFIX.length()));
            else permissions.add(a);
        });
        return new MeResponse(auth.getName(), roles, permissions, null);
    }
}
