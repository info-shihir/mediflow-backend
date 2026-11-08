package com.example.secure.user;

import com.example.secure.shared.Errors;
import java.util.Locale;
import org.springframework.stereotype.Component;

/** NIST-style: length over composition rules. Extend here (e.g. breached-password check). */
@Component
class PasswordPolicy {

    void validate(String raw, String username) {
        if (raw.length() < 12 || raw.length() > 128) {
            throw new Errors.Invalid("Password must be 12 to 128 characters");
        }
        if (raw.toLowerCase(Locale.ROOT).contains(username.toLowerCase(Locale.ROOT))) {
            throw new Errors.Invalid("Password must not contain the username");
        }
    }
}
