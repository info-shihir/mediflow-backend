create table permissions (
    id          bigserial primary key,
    name        varchar(100) not null unique,
    description varchar(255)
);

create table roles (
    id   bigserial primary key,
    name varchar(50) not null unique
);

create table role_permissions (
    role_id       bigint not null references roles (id) on delete cascade,
    permission_id bigint not null references permissions (id) on delete cascade,
    primary key (role_id, permission_id)
);

create table users (
    id              bigserial primary key,
    username        varchar(100) not null,
    password_hash   varchar(255) not null,
    enabled         boolean      not null default true,
    failed_attempts integer      not null default 0,
    locked_until    timestamptz,
    created_at      timestamptz  not null default now(),
    version         bigint       not null default 0
);
create unique index ux_users_username_lower on users (lower(username));

create table user_roles (
    user_id bigint not null references users (id) on delete cascade,
    role_id bigint not null references roles (id) on delete cascade,
    primary key (user_id, role_id)
);

create table audit_events (
    id          bigserial primary key,
    occurred_at timestamptz  not null,
    type        varchar(40)  not null,
    principal   varchar(100),
    ip          varchar(64),
    detail      varchar(500)
);
create index ix_audit_occurred_at on audit_events (occurred_at desc);

create table orders (
    id         bigserial primary key,
    title      varchar(200) not null,
    owner      varchar(100) not null,
    created_at timestamptz  not null default now()
);
create index ix_orders_owner on orders (owner);

-- Permissions are code-defined: adding one = a migration + a hasPermission(...) call.
insert into permissions (name, description) values
  ('user:read',      'List users'),
  ('user:create',    'Create users'),
  ('user:update',    'Change user roles / enabled flag'),
  ('role:read',      'List roles and permissions'),
  ('role:create',    'Create roles'),
  ('role:update',    'Change role permissions'),
  ('session:revoke', 'Force-logout a user'),
  ('audit:read',     'Read the audit log'),
  ('order:read',     'Read own orders'),
  ('order:create',   'Create orders'),
  ('order:update',   'Update own orders'),
  ('order:delete',   'Delete own orders'),
  ('order:read-all', 'Read everyone''s orders'),
  ('order:manage-all','Update/delete everyone''s orders');

insert into roles (name) values ('ADMIN'), ('USER');

insert into role_permissions (role_id, permission_id)
select r.id, p.id from roles r cross join permissions p where r.name = 'ADMIN';

insert into role_permissions (role_id, permission_id)
select r.id, p.id from roles r join permissions p
  on p.name in ('order:read', 'order:create', 'order:update', 'order:delete')
where r.name = 'USER';
