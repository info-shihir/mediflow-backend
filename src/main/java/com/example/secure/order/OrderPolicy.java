package com.example.secure.order;

import com.example.secure.access.OwnedResourcePolicy;
import java.io.Serializable;
import java.util.Optional;
import org.springframework.stereotype.Component;

/** The whole instance-level rule set for orders: "say who the owner is". */
@Component
class OrderPolicy extends OwnedResourcePolicy {

    private final OrderRepository orders;

    OrderPolicy(OrderRepository orders) {
        this.orders = orders;
    }

    @Override
    public String type() { return "Order"; }

    @Override
    protected Optional<String> ownerOf(Serializable id) {
        return id instanceof Number n ? orders.findById(n.longValue()).map(Order::getOwner) : Optional.empty();
    }
}
