package com.example.secure.access;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import java.util.Set;

public final class RoleDtos {
    private RoleDtos() {}

    public record RoleView(Long id, String name, Set<String> permissions) {}

    public record PermissionView(String name, String description) {}

    public record CreateRole(
        @NotBlank @Pattern(regexp = "[A-Z][A-Z_]{1,49}") String name,
        Set<@NotBlank String> permissions) {}

    public record SetPermissions(Set<@NotBlank String> permissions) {}
}
