package com.example.secure.user;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.Set;

public final class UserDtos {
    private UserDtos() {}

    public record UserView(Long id, String username, boolean enabled, boolean locked, Set<String> roles) {}

    public record CreateUser(
        @NotBlank @Size(min = 3, max = 100) @Pattern(regexp = "[A-Za-z0-9._-]+") String username,
        @NotBlank @Size(max = 128) String password,
        @NotEmpty Set<@NotBlank String> roles) {}

    public record SetRoles(@NotEmpty Set<@NotBlank String> roles) {}

    public record SetEnabled(boolean enabled) {}
}
