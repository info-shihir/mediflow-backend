package com.example.secure.audit;

import java.time.Instant;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/** Single entry point for security audit records. IP is picked up from the current request. */
@Service
public class AuditService {

    public record AuditView(Long id, Instant occurredAt, AuditType type, String principal, String ip, String detail) {}

    private final AuditEventRepository events;

    AuditService(AuditEventRepository events) {
        this.events = events;
    }

    /** REQUIRES_NEW: the record survives even if the caller's transaction rolls back. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(AuditType type, String principal, String detail) {
        events.save(new AuditEvent(type, cut(principal, 100), currentIp(), cut(detail, 500)));
    }

    @Transactional(readOnly = true)
    public Page<AuditView> page(Pageable pageable) {
        return events.findAll(pageable).map(e ->
            new AuditView(e.getId(), e.getOccurredAt(), e.getType(), e.getPrincipal(), e.getIp(), e.getDetail()));
    }

    private static String currentIp() {
        return RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes a
            ? a.getRequest().getRemoteAddr() : null;
    }

    private static String cut(String s, int max) {
        return s == null || s.length() <= max ? s : s.substring(0, max);
    }
}
