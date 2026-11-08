package com.example.secure.order;

import com.example.secure.access.Grants;
import com.example.secure.order.OrderDtos.OrderView;
import com.example.secure.shared.Errors;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class OrderService {

    private final OrderRepository orders;

    OrderService(OrderRepository orders) {
        this.orders = orders;
    }

    /** Row filtering happens in the query, never after loading. */
    @Transactional(readOnly = true)
    public Page<OrderView> list(Authentication auth, Pageable pageable) {
        Page<Order> page = Grants.has(auth, "order:read-all")
            ? orders.findAll(pageable)
            : orders.findByOwner(auth.getName(), pageable);
        return page.map(OrderView::from);
    }

    @Transactional(readOnly = true)
    public OrderView get(Long id) { return OrderView.from(find(id)); }

    public OrderView create(String title, Authentication auth) {
        return OrderView.from(orders.save(new Order(title, auth.getName())));
    }

    public OrderView update(Long id, String title) {
        Order order = find(id);
        order.rename(title);
        return OrderView.from(order);
    }

    public void delete(Long id) { orders.delete(find(id)); }

    private Order find(Long id) {
        return orders.findById(id).orElseThrow(() -> new Errors.NotFound("Order not found"));
    }
}
