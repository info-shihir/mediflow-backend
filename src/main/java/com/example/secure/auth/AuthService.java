package com.example.secure.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;

@Service
class AuthService {

    private final AuthenticationManager authenticationManager;
    private final SessionAuthenticationStrategy sessionStrategy;
    private final SecurityContextRepository contextRepository;
    private final JwtUtil jwtUtil;
    private final SecurityContextHolderStrategy holder = SecurityContextHolder.getContextHolderStrategy();

    AuthService(AuthenticationManager authenticationManager,
                SessionAuthenticationStrategy sessionStrategy,
                SecurityContextRepository contextRepository,
                JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.sessionStrategy = sessionStrategy;
        this.contextRepository = contextRepository;
        this.jwtUtil = jwtUtil;
    }

    MeResponse login(LoginRequest req, HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(req.username(), req.password()));
        } catch (AuthenticationException _) {
            // unknown user, wrong password, locked, disabled: all look identical to the client
            throw new BadCredentialsException("Invalid credentials");
        }

        sessionStrategy.onAuthentication(authentication, request, response);   // limit, fixation, CSRF rotation

        SecurityContext context = holder.createEmptyContext();
        context.setAuthentication(authentication);
        holder.setContext(context);
        contextRepository.saveContext(context, request, response);             // writes the session
        MeResponse base = MeResponse.from(authentication);
        String token = jwtUtil.generateToken(authentication);
        return new MeResponse(base.username(), base.roles(), base.permissions(), token);
    }
}
