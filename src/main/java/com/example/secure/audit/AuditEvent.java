package com.example.secure.audit;

import jakarta.persistence.*;
import java.time.Instant;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "audit_events")
public class AuditEvent {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @CreationTimestamp
    @Column(updatable = false)
    private Instant occurredAt;

    @Enumerated(EnumType.STRING)
    private AuditType type;

    private String principal;
    private String ip;
    private String detail;

    protected AuditEvent() {}

    AuditEvent(AuditType type, String principal, String ip, String detail) {
        this.type = type;
        this.principal = principal;
        this.ip = ip;
        this.detail = detail;
    }

    Long getId() { return id; }
    Instant getOccurredAt() { return occurredAt; }
    AuditType getType() { return type; }
    String getPrincipal() { return principal; }
    String getIp() { return ip; }
    String getDetail() { return detail; }
}
