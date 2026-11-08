package com.example.secure.user;

import com.example.secure.user.UserDtos.*;
import jakarta.validation.Valid;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PagedModel;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/** Thin: authorize, delegate, return. All rules live in UserAdminService. */
@RestController
@RequestMapping("/api/admin/users")
public class UserAdminController {

    private final UserAdminService service;

    public UserAdminController(UserAdminService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize("hasPermission('User', 'read')")
    public PagedModel<UserView> list(Pageable pageable) {
        return new PagedModel<>(service.list(pageable));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasPermission('User', 'create')")
    public UserView create(@Valid @RequestBody CreateUser req, Authentication actor) {
        return service.create(req.username(), req.password(), req.roles(), actor);
    }

    @PutMapping("/{id}/roles")
    @PreAuthorize("hasPermission('User', 'update')")
    public UserView setRoles(@PathVariable Long id, @Valid @RequestBody SetRoles req, Authentication actor) {
        return service.setRoles(id, req.roles(), actor);
    }

    @PutMapping("/{id}/enabled")
    @PreAuthorize("hasPermission('User', 'update')")
    public UserView setEnabled(@PathVariable Long id, @RequestBody SetEnabled req, Authentication actor) {
        return service.setEnabled(id, req.enabled(), actor);
    }

    @DeleteMapping("/{id}/sessions")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasPermission('Session', 'revoke')")
    public void revokeSessions(@PathVariable Long id, Authentication actor) {
        service.revokeSessions(id, actor);
    }
}
