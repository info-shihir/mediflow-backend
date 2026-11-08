package com.example.secure.access;

import java.io.Serializable;
import java.util.Optional;
import org.springframework.security.core.Authentication;

/**
 * Ready-made rule for "someone owns it": owner, or holder of "<type>:manage-all",
 * or (for reads) holder of "<type>:read-all". Subclasses only say who the owner is.
 */
public abstract class OwnedResourcePolicy implements ResourcePolicy {

    protected abstract Optional<String> ownerOf(Serializable id);

    @Override
    public boolean canAccess(Authentication auth, Serializable id, String action) {
        return ownerOf(id)
            .map(owner -> owner.equals(auth.getName())
                || Grants.has(auth, Grants.name(type(), "manage-all"))
                || ("read".equals(action) && Grants.has(auth, Grants.name(type(), "read-all"))))
            .orElse(false);   // unknown id => deny (never reveals existence)
    }
}
