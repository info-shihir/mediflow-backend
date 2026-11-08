package com.example.secure.access;

import java.io.Serializable;
import org.springframework.security.core.Authentication;

/**
 * Instance-level rule for one resource type (ownership, tenant, status...).
 * Add a resource = add one @Component implementing this. Nothing else changes (open/closed).
 * The type-level permission (e.g. "order:update") is already verified before canAccess runs.
 */
public interface ResourcePolicy {
    String type();

    boolean canAccess(Authentication auth, Serializable id, String action);
}
