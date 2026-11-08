package com.example.secure.user;

import com.example.secure.access.RolePermissionsChanged;
import com.example.secure.session.SessionRevoker;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionalEventListener;

/** When a role's permissions change, everyone holding that role must log in again. */
@Component
class AccessChangeListener {

    private final UserRepository users;
    private final SessionRevoker sessions;

    AccessChangeListener(UserRepository users, SessionRevoker sessions) {
        this.users = users;
        this.sessions = sessions;
    }

    @TransactionalEventListener   // after the role change has committed
    void on(RolePermissionsChanged event) {
        users.findUsernamesByRoleId(event.roleId()).forEach(sessions::revokeAll);
    }
}
