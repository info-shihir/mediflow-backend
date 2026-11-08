package com.example.secure.access;

import java.util.Locale;
import org.springframework.security.core.Authentication;

/** The only place that knows how a permission string is built and checked. */
public final class Grants {
    private Grants() {}

    /** ("Order", "update") -> "order:update" */
    public static String name(String type, String action) {
        return type.toLowerCase(Locale.ROOT) + ":" + action;
    }

    public static boolean has(Authentication auth, String permission) {
        return auth != null && auth.isAuthenticated()
            && auth.getAuthorities().stream().anyMatch(g -> permission.equals(g.getAuthority()));
    }
}
