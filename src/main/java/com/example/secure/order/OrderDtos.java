package com.example.secure.order;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;

public final class OrderDtos {
    private OrderDtos() {}

    public record OrderRequest(@NotBlank @Size(max = 200) String title) {}

    public record OrderView(Long id, String title, String owner, Instant createdAt) {
        static OrderView from(Order o) {
            return new OrderView(o.getId(), o.getTitle(), o.getOwner(), o.getCreatedAt());
        }
    }
}
