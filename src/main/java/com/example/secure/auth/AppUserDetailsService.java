package com.example.secure.auth;

import com.example.secure.user.UserAccount;
import com.example.secure.user.UserRepository;
import java.time.Clock;
import java.util.HashSet;
import java.util.Set;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Roles become ROLE_X authorities; each role's permissions become plain "resource:action" authorities. */
@Service
class AppUserDetailsService implements UserDetailsService {

    private final UserRepository users;
    private final Clock clock;

    AppUserDetailsService(UserRepository users, Clock clock) {
        this.users = users;
        this.clock = clock;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) {
        UserAccount u = users.findByUsernameIgnoreCase(username)
            .orElseThrow(() -> new UsernameNotFoundException("unknown user"));

        Set<GrantedAuthority> authorities = new HashSet<>();
        u.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));
            role.getPermissions().forEach(p -> authorities.add(new SimpleGrantedAuthority(p.getName())));
        });
        return new AppUser(u.getId(), u.getUsername(), u.getPasswordHash(),
            u.isEnabled(), !u.isLocked(clock.instant()), authorities);
    }
}
