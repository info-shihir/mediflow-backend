package com.example.secure.order;

import jakarta.persistence.*;
import java.time.Instant;
import org.hibernate.annotations.CreationTimestamp;

@Entity(name = "CustomerOrder")   // avoids the JPQL keyword "Order"
@Table(name = "orders")
public class Order {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String title;

    @Column(nullable = false, updatable = false)
    private String owner;

    @CreationTimestamp
    @Column(updatable = false)
    private Instant createdAt;

    protected Order() {}

    public Order(String title, String owner) {
        this.title = title;
        this.owner = owner;
    }

    public void rename(String title) { this.title = title; }

    public Long getId() { return id; }
    public String getTitle() { return title; }
    public String getOwner() { return owner; }
    public Instant getCreatedAt() { return createdAt; }
}
