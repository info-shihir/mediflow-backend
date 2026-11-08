package com.example.secure.order;

import com.example.secure.order.OrderDtos.*;
import jakarta.validation.Valid;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PagedModel;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private final OrderService service;

    OrderController(OrderService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize("hasPermission('Order', 'read')")
    public PagedModel<OrderView> list(Authentication auth, Pageable pageable) {
        return new PagedModel<>(service.list(auth, pageable));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasPermission(#id, 'Order', 'read')")
    public OrderView get(@PathVariable Long id) { return service.get(id); }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasPermission('Order', 'create')")
    public OrderView create(@Valid @RequestBody OrderRequest req, Authentication auth) {
        return service.create(req.title(), auth);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasPermission(#id, 'Order', 'update')")
    public OrderView update(@PathVariable Long id, @Valid @RequestBody OrderRequest req) {
        return service.update(id, req.title());
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasPermission(#id, 'Order', 'delete')")
    public void delete(@PathVariable Long id) { service.delete(id); }
}
