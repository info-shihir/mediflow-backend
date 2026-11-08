package com.example.secure.access;

import com.example.secure.access.RoleDtos.*;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/admin")
public class RoleAdminController {

    private final RoleAdminService service;

    public RoleAdminController(RoleAdminService service) {
        this.service = service;
    }

    @GetMapping("/roles")
    @PreAuthorize("hasPermission('Role', 'read')")
    public List<RoleView> roles() { return service.listRoles(); }

    @GetMapping("/permissions")
    @PreAuthorize("hasPermission('Role', 'read')")
    public List<PermissionView> permissions() { return service.listPermissions(); }

    @PostMapping("/roles")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasPermission('Role', 'create')")
    public RoleView create(@Valid @RequestBody CreateRole req, Authentication actor) {
        return service.create(req.name(), req.permissions(), actor);
    }

    @PutMapping("/roles/{id}/permissions")
    @PreAuthorize("hasPermission('Role', 'update')")
    public RoleView setPermissions(@PathVariable Long id, @Valid @RequestBody SetPermissions req, Authentication actor) {
        return service.setPermissions(id, req.permissions(), actor);
    }
}
