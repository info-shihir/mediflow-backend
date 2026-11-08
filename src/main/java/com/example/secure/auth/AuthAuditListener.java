package com.example.secure.auth;

import com.example.secure.audit.AuditService;
import com.example.secure.audit.AuditType;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

/** Real failure reason (locked, disabled, bad password...) goes to the audit log; the client only sees 401. */
@Component
class AuthAuditListener {

    private final AuditService audit;

    AuthAuditListener(AuditService audit) {
        this.audit = audit;
    }

    @EventListener
    void onSuccess(AuthenticationSuccessEvent e) {
        audit.record(AuditType.LOGIN_SUCCESS, e.getAuthentication().getName(), null);
    }

    @EventListener
    void onFailure(AbstractAuthenticationFailureEvent e) {
        audit.record(AuditType.LOGIN_FAILURE, e.getAuthentication().getName(), e.getException().getClass().getSimpleName());
    }
}
