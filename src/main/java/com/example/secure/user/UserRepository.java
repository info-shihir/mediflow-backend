package com.example.secure.user;

import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

public interface UserRepository extends JpaRepository<UserAccount, Long> {

    /** Login lookup: roles and permissions in one query. */
    @EntityGraph(attributePaths = {"roles", "roles.permissions"})
    Optional<UserAccount> findByUsernameIgnoreCase(String username);

    boolean existsByUsernameIgnoreCase(String username);

    /** Row lock => concurrent failed logins cannot race past the lockout threshold. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from UserAccount u where lower(u.username) = lower(:username)")
    Optional<UserAccount> lockByUsername(String username);

    @Modifying
    @Query("""
        update UserAccount u set u.failedAttempts = 0, u.lockedUntil = null
        where lower(u.username) = lower(:username)
          and (u.failedAttempts > 0 or u.lockedUntil is not null)""")
    int resetFailures(String username);

    @Query("select u.username from UserAccount u join u.roles r where r.id = :roleId")
    List<String> findUsernamesByRoleId(Long roleId);
}
