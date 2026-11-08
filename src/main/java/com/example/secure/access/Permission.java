package com.example.secure.access;

import jakarta.persistence.*;

@Entity
@Table(name = "permissions")
public class Permission {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, updatable = false)
    private String name;          // "order:update"

    private String description;

    protected Permission() {}

    public Long getId() { return id; }
    public String getName() { return name; }
    public String getDescription() { return description; }
}
