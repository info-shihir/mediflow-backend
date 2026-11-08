package com.example.secure.shared;

/** Domain errors. Services throw these; GlobalExceptionHandler maps them to HTTP. */
public final class Errors {
    private Errors() {}

    public static class NotFound extends RuntimeException {
        public NotFound(String message) { super(message); }
    }

    public static class Conflict extends RuntimeException {
        public Conflict(String message) { super(message); }
    }

    public static class Invalid extends RuntimeException {
        public Invalid(String message) { super(message); }
    }
}
