package com.example.secure.user;

import com.example.secure.access.Role;
import com.example.secure.config.SecurityProps;
import jakarta.persistence.*;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import org.hibernate.annotations.CreationTimestamp;

/** Rich entity: lockout rules live here, not in a service. */
@Entity
@Table(name = "users")
public class UserAccount {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String username;                      // always stored lower-case

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    private boolean enabled = true;
    private int failedAttempts;
    private Instant lockedUntil;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    @CreationTimestamp
    @Column(updatable = false)
    private Instant createdAt;

    @Version
    private long version;

    protected UserAccount() {}

    public UserAccount(String username, String passwordHash) {
        this.username = username.toLowerCase(Locale.ROOT);
        this.passwordHash = passwordHash;
    }

    public boolean isLocked(Instant now) {
        return lockedUntil != null && lockedUntil.isAfter(now);
    }

    /** Progressive lockout: base * 2^(failures beyond the threshold), capped at maxDuration. */
    public void registerFailure(SecurityProps.Lockout policy, Instant now) {
        failedAttempts++;
        if (failedAttempts >= policy.maxAttempts()) {
            long doublings = Math.min(failedAttempts - policy.maxAttempts(), 20);
            Duration lock = policy.baseDuration().multipliedBy(1L << doublings);
            if (lock.compareTo(policy.maxDuration()) > 0) lock = policy.maxDuration();
            lockedUntil = now.plus(lock);
        }
    }

    public void replaceRoles(Set<Role> newRoles) {
        roles.clear();
        roles.addAll(newRoles);
    }

    public Long getId() { return id; }
    public String getUsername() { return username; }
    public String getPasswordHash() { return passwordHash; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public Set<Role> getRoles() { return roles; }
}
