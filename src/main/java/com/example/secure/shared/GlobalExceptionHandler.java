package com.example.secure.shared;

import com.example.secure.audit.AuditService;
import com.example.secure.audit.AuditType;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/** One place that turns exceptions into RFC 9457 problem responses. Never leaks internals. */
@RestControllerAdvice
class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private final AuditService audit;

    GlobalExceptionHandler(AuditService audit) {
        this.audit = audit;
    }

    @ExceptionHandler(AuthenticationException.class)
    ProblemDetail unauthenticated(AuthenticationException e) {
        return problem(HttpStatus.UNAUTHORIZED, "Invalid credentials");
    }

    @ExceptionHandler(AccessDeniedException.class)
    ProblemDetail denied(AccessDeniedException e, HttpServletRequest request) {
        String who = request.getUserPrincipal() != null ? request.getUserPrincipal().getName() : "anonymous";
        audit.record(AuditType.ACCESS_DENIED, who, request.getMethod() + " " + request.getRequestURI());
        return problem(HttpStatus.FORBIDDEN, "Access denied");
    }

    @ExceptionHandler(Errors.NotFound.class)
    ProblemDetail notFound(Errors.NotFound e) { return problem(HttpStatus.NOT_FOUND, e.getMessage()); }

    @ExceptionHandler(Errors.Conflict.class)
    ProblemDetail conflict(Errors.Conflict e) { return problem(HttpStatus.CONFLICT, e.getMessage()); }

    @ExceptionHandler(Errors.Invalid.class)
    ProblemDetail invalid(Errors.Invalid e) { return problem(HttpStatus.BAD_REQUEST, e.getMessage()); }

    @ExceptionHandler(DataIntegrityViolationException.class)
    ProblemDetail integrity(DataIntegrityViolationException e) { return problem(HttpStatus.CONFLICT, "Conflicting data"); }

    @ExceptionHandler(Exception.class)
    ProblemDetail unexpected(Exception e) {
        log.error("Unhandled error", e);
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "Unexpected error");
    }

    private static ProblemDetail problem(HttpStatus status, String detail) {
        return ProblemDetail.forStatusAndDetail(status, detail);
    }
}
