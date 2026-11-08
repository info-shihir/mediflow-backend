package com.example.secure.user;

import com.example.secure.access.RoleRepository;
import com.example.secure.config.SecurityProps;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

/** First start only: creates the initial admin from env, so no default password ever exists in code or SQL. */
@Component
class BootstrapAdmin implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BootstrapAdmin.class);

    private final UserRepository users;
    private final RoleRepository roles;
    private final PasswordEncoder encoder;
    private final PasswordPolicy policy;
    private final SecurityProps props;

    BootstrapAdmin(UserRepository users, RoleRepository roles, PasswordEncoder encoder,
                   PasswordPolicy policy, SecurityProps props) {
        this.users = users;
        this.roles = roles;
        this.encoder = encoder;
        this.policy = policy;
        this.props = props;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        var cfg = props.bootstrap();
        if (users.count() > 0 || !StringUtils.hasText(cfg.adminPassword())) return;

        policy.validate(cfg.adminPassword(), cfg.adminUsername());
        var admin = new UserAccount(cfg.adminUsername(), encoder.encode(cfg.adminPassword()));
        admin.replaceRoles(Set.of(roles.findByName("ADMIN").orElseThrow()));
        users.save(admin);
        log.info("Bootstrap admin '{}' created. Remove BOOTSTRAP_ADMIN_PASSWORD from the environment.", admin.getUsername());
    }
}
