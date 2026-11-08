package com.example.secure.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Max lengths bound the cost of hashing attacker-supplied input. */
public record LoginRequest(
    @NotBlank @Size(max = 100) String username,
    @NotBlank @Size(max = 128) String password) {}
