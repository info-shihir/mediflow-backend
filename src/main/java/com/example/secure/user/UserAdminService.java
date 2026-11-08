package com.example.secure.user;

import com.example.secure.access.Grants;
import com.example.secure.access.Permission;
import com.example.secure.access.Role;
import com.example.secure.access.RoleRepository;
import com.example.secure.audit.AuditService;
import com.example.secure.audit.AuditType;
import com.example.secure.session.SessionRevoker;
import com.example.secure.shared.Errors;
import com.example.secure.user.UserDtos.UserView;
import java.time.Clock;
import java.util.Collection;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Anti-escalation rules (enforced here, once):
 *  1. you cannot change your own roles / enabled flag;
 *  2. you can only grant or touch roles whose permissions you hold yourself.
 */
@Service
@Transactional
public class UserAdminService {

    private final UserRepository users;
    private final RoleRepository roles;
    private final PasswordEncoder encoder;
    private final PasswordPolicy passwordPolicy;
    private final SessionRevoker sessions;
    private final AuditService audit;
    private final Clock clock;

    UserAdminService(UserRepository users, RoleRepository roles, PasswordEncoder encoder,
                     PasswordPolicy passwordPolicy, SessionRevoker sessions, AuditService audit, Clock clock) {
        this.users = users;
        this.roles = roles;
        this.encoder = encoder;
        this.passwordPolicy = passwordPolicy;
        this.sessions = sessions;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public Page<UserView> list(Pageable pageable) {
        return users.findAll(pageable).map(this::view);
    }

    public UserView create(String username, String password, Set<String> roleNames, Authentication actor) {
        if (users.existsByUsernameIgnoreCase(username)) throw new Errors.Conflict("Username already taken");
        passwordPolicy.validate(password, username);
        Set<Role> granted = resolveRoles(roleNames, actor);

        var user = new UserAccount(username, encoder.encode(password));
        user.replaceRoles(granted);
        users.save(user);
        audit.record(AuditType.USER_CREATED, actor.getName(), user.getUsername());
        return view(user);
    }

    public UserView setRoles(Long id, Set<String> roleNames, Authentication actor) {
        UserAccount user = load(id);
        rejectSelf(user, actor);
        requireHolds(actor, user.getRoles());                 // cannot modify someone more powerful
        user.replaceRoles(resolveRoles(roleNames, actor));
        sessions.revokeAll(user.getUsername());               // new permissions apply on next login
        audit.record(AuditType.USER_ROLES_CHANGED, actor.getName(), user.getUsername() + " -> " + roleNames);
        return view(user);
    }

    public UserView setEnabled(Long id, boolean enabled, Authentication actor) {
        UserAccount user = load(id);
        rejectSelf(user, actor);
        requireHolds(actor, user.getRoles());
        user.setEnabled(enabled);
        if (!enabled) sessions.revokeAll(user.getUsername());
        audit.record(AuditType.USER_ENABLED_CHANGED, actor.getName(), user.getUsername() + " enabled=" + enabled);
        return view(user);
    }

    public void revokeSessions(Long id, Authentication actor) {
        UserAccount user = load(id);
        sessions.revokeAll(user.getUsername());
        audit.record(AuditType.SESSIONS_REVOKED, actor.getName(), user.getUsername());
    }

    // ---- helpers ----

    private UserAccount load(Long id) {
        return users.findById(id).orElseThrow(() -> new Errors.NotFound("User not found"));
    }

    private Set<Role> resolveRoles(Set<String> names, Authentication actor) {
        Set<Role> found = Set.copyOf(roles.findByNameIn(names));
        if (found.size() != names.size()) throw new Errors.Invalid("Unknown role in request");
        requireHolds(actor, found);
        return found;
    }

    private static void requireHolds(Authentication actor, Collection<Role> targetRoles) {
        boolean ok = targetRoles.stream()
            .flatMap(r -> r.getPermissions().stream())
            .map(Permission::getName)
            .allMatch(p -> Grants.has(actor, p));
        if (!ok) throw new AccessDeniedException("Cannot grant or modify permissions you do not hold");
    }

    private static void rejectSelf(UserAccount target, Authentication actor) {
        if (target.getUsername().equalsIgnoreCase(actor.getName())) {
            throw new Errors.Conflict("You cannot change your own roles or status");
        }
    }

    private UserView view(UserAccount u) {
        Set<String> roleNames = u.getRoles().stream().map(Role::getName).collect(Collectors.toCollection(TreeSet::new));
        return new UserView(u.getId(), u.getUsername(), u.isEnabled(), u.isLocked(clock.instant()), roleNames);
    }
}
