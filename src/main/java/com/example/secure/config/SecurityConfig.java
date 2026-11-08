package com.example.secure.config;

import java.util.List;
import java.util.Map;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.session.*;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;
import com.example.secure.auth.JwtUtil;
import com.example.secure.auth.JwtAuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * HTTP-level security only: filter chain, sessions, CSRF, headers, password hashing.
 * Authorization rules live next to the code they protect (@PreAuthorize + hasPermission).
 */
@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http,
                                    SecurityContextRepository contextRepository,
                                    CsrfTokenRepository csrfRepository,
                                    SessionAuthenticationStrategy sessionStrategy,
                                    SessionRegistry sessionRegistry,
                                    SecurityProps props, JwtUtil jwtUtil) throws Exception {
        return http
            .authorizeHttpRequests(a -> a
                .requestMatchers("/api/auth/login", "/api/auth/csrf", "/actuator/health/**").permitAll()
                .requestMatchers("/api/**").authenticated()
                .anyRequest().permitAll())                       // static Angular files, if served from here
            .securityContext(c -> c.securityContextRepository(contextRepository))
            .csrf(c -> c.csrfTokenRepository(csrfRepository)
                        .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler()))
            .sessionManagement(s -> s
                .sessionAuthenticationStrategy(sessionStrategy)
                .sessionConcurrency(c -> c.maximumSessions(props.maxSessions()).sessionRegistry(sessionRegistry)))
            .exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
            .logout(l -> l.logoutUrl("/api/auth/logout")
                .deleteCookies("SESSION")
                .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler()))
            .headers(h -> h
                .contentSecurityPolicy(c -> c.policyDirectives(
                    "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'"))
                .httpStrictTransportSecurity(s -> s.includeSubDomains(true).maxAgeInSeconds(31_536_000))
                .referrerPolicy(r -> r.policy(ReferrerPolicy.NO_REFERRER))
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny))
                            .addFilterBefore(new JwtAuthenticationFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    // ---- sessions (stored in Postgres via Spring Session JDBC => any node can serve any request) ----

    @Bean
    SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    CsrfTokenRepository csrfTokenRepository() {
        return CookieCsrfTokenRepository.withHttpOnlyFalse();
    }

    @Bean
    <S extends Session> SessionRegistry sessionRegistry(FindByIndexNameSessionRepository<S> repository) {
        return new SpringSessionBackedSessionRegistry<>(repository);
    }

    /** Applied by AuthService on our JSON login: concurrency limit, fixation protection, CSRF rotation. */
    @Bean
    SessionAuthenticationStrategy sessionAuthenticationStrategy(SessionRegistry registry,
                                                                CsrfTokenRepository csrfRepository,
                                                                SecurityProps props) {
        var concurrency = new ConcurrentSessionControlAuthenticationStrategy(registry);
        concurrency.setMaximumSessions(props.maxSessions());
        return new CompositeSessionAuthenticationStrategy(List.of(
            concurrency,
            new ChangeSessionIdAuthenticationStrategy(),
            new RegisterSessionAuthenticationStrategy(registry),
            new CsrfAuthenticationStrategy(csrfRepository)));
    }

    // ---- authentication ----

    @Bean
    PasswordEncoder passwordEncoder() {
        return new DelegatingPasswordEncoder("argon2", Map.of(
            "argon2", Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(),
            "bcrypt", new BCryptPasswordEncoder(12)));   // legacy hashes stay valid; new ones use Argon2id
    }
    @Bean
    public JwtUtil jwtUtil() {
        return new JwtUtil();
    }

    @Bean
    AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher publisher) {
        return new DefaultAuthenticationEventPublisher(publisher);
    }

    @Bean
    AuthenticationManager authenticationManager(UserDetailsService users,
                                                PasswordEncoder encoder,
                                                AuthenticationEventPublisher publisher) {
        var provider = new DaoAuthenticationProvider(users);
        provider.setPasswordEncoder(encoder);
        var manager = new ProviderManager(provider);
        manager.setAuthenticationEventPublisher(publisher);   // feeds lockout + audit listeners
        return manager;
    }
}
