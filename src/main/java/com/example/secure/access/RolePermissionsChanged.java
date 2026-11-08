package com.example.secure.access;

/** Published after a role's permissions change, so other modules can react (e.g. revoke sessions). */
public record RolePermissionsChanged(Long roleId) {}
