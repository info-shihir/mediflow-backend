package com.example.secure.auth;

import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

/** Session principal: Spring's User (serializable, erases its password) plus our id. */
public class AppUser extends User {

    private static final long serialVersionUID = 1L;

    private final Long id;

    public AppUser(Long id, String username, String password, boolean enabled, boolean nonLocked,
                   Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, true, true, nonLocked, authorities);
        this.id = id;
    }

    public Long getId() { return id; }
}
