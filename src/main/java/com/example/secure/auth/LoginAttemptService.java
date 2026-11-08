package com.example.secure.auth;

import com.example.secure.config.SecurityProps;
import com.example.secure.user.UserRepository;
import java.time.Clock;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Reacts to Spring Security's own events: AuthService never needs to know lockout exists. */
@Service
public class LoginAttemptService {

    private final UserRepository users;
    private final SecurityProps props;
    private final Clock clock;

    LoginAttemptService(UserRepository users, SecurityProps props, Clock clock) {
        this.users = users;
        this.props = props;
        this.clock = clock;
    }

    @EventListener
    @Transactional
    public void onBadCredentials(AuthenticationFailureBadCredentialsEvent event) {
        users.lockByUsername(event.getAuthentication().getName())     // unknown user => no-op
             .ifPresent(u -> u.registerFailure(props.lockout(), clock.instant()));
    }

    @EventListener
    @Transactional
    public void onSuccess(AuthenticationSuccessEvent event) {
        users.resetFailures(event.getAuthentication().getName());
    }
}
