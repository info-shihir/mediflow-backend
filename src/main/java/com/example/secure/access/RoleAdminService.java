package com.example.secure.access;

import com.example.secure.access.RoleDtos.PermissionView;
import com.example.secure.access.RoleDtos.RoleView;
import com.example.secure.audit.AuditService;
import com.example.secure.audit.AuditType;
import com.example.secure.shared.Errors;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class RoleAdminService {

    private static final String PROTECTED_ROLE = "ADMIN";

    private final RoleRepository roles;
    private final PermissionRepository permissions;
    private final ApplicationEventPublisher events;
    private final AuditService audit;

    RoleAdminService(RoleRepository roles, PermissionRepository permissions,
                     ApplicationEventPublisher events, AuditService audit) {
        this.roles = roles;
        this.permissions = permissions;
        this.events = events;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public List<RoleView> listRoles() {
        return roles.findAllBy().stream().map(RoleAdminService::view)
                    .sorted(Comparator.comparing(RoleView::name)).toList();
    }

    @Transactional(readOnly = true)
    public List<PermissionView> listPermissions() {
        return permissions.findAll().stream().map(p -> new PermissionView(p.getName(), p.getDescription()))
                          .sorted(Comparator.comparing(PermissionView::name)).toList();
    }

    public RoleView create(String name, Set<String> permissionNames, Authentication actor) {
        if (roles.findByName(name).isPresent()) throw new Errors.Conflict("Role already exists");
        var role = new Role(name);
        role.replacePermissions(resolve(permissionNames, actor));
        roles.save(role);
        audit.record(AuditType.ROLE_CREATED, actor.getName(), name);
        return view(role);
    }

    public RoleView setPermissions(Long id, Set<String> permissionNames, Authentication actor) {
        Role role = roles.findWithPermissionsById(id).orElseThrow(() -> new Errors.NotFound("Role not found"));
        if (PROTECTED_ROLE.equals(role.getName())) throw new Errors.Conflict("ADMIN role is immutable");
        requireHolds(actor, role.getPermissions());          // cannot edit a role more powerful than you
        role.replacePermissions(resolve(permissionNames, actor));
        events.publishEvent(new RolePermissionsChanged(role.getId()));
        audit.record(AuditType.ROLE_PERMISSIONS_CHANGED, actor.getName(), role.getName() + " -> " + permissionNames);
        return view(role);
    }

    /** Names -> entities; unknown names are rejected; no privilege escalation. */
    private Set<Permission> resolve(Set<String> names, Authentication actor) {
        Set<Permission> found = Set.copyOf(permissions.findByNameIn(names));
        if (found.size() != names.size()) throw new Errors.Invalid("Unknown permission in request");
        requireHolds(actor, found);
        return found;
    }

    private static void requireHolds(Authentication actor, Set<Permission> required) {
        if (!required.stream().allMatch(p -> Grants.has(actor, p.getName()))) {
            throw new AccessDeniedException("Cannot grant or modify permissions you do not hold");
        }
    }

    private static RoleView view(Role r) {
        return new RoleView(r.getId(), r.getName(),
            r.getPermissions().stream().map(Permission::getName).collect(Collectors.toCollection(java.util.TreeSet::new)));
    }
}
