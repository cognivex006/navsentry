# Orders — own order, other reader, anonymous, lower role

Synthetic fixture flow (127.0.0.1 only). Reader A can read their order; reader B,
an anonymous visitor and a reader on the admin function must be denied.

```navsentry-flow
{
  "flow": "1",
  "id": "orders-access",
  "title": "Orders access control",
  "story": "A reader opens their own order; another reader and an anonymous visitor cannot; only admins see stats.",
  "level": "integration",
  "actors": ["reader_a", "reader_b", "admin", "anonymous"],
  "tags": ["orders", "access-control"],
  "review": { "status": "draft" },
  "provenance": { "kind": "human", "sources": ["fixture"] }
}
```

## S1 — Reader A lists orders

```navsentry-step
{
  "id": "S1", "action": "http", "actor": "reader_a",
  "request": { "method": "GET", "path": "/api/orders", "accept": "json" },
  "expect": { "status": [200], "content_type": "application/json", "json": [{ "pointer": "/items", "type": "array", "min_items": 1 }] },
  "extract": { "orderA": { "from": "json", "pointer": "/items/0/id" } }
}
```

## S2 — Reader A opens own order (positive control)

```navsentry-step
{
  "id": "S2", "action": "http", "actor": "reader_a",
  "request": { "method": "GET", "path": "/api/orders/{{orderA}}", "accept": "json" },
  "expect": { "access": "allowed", "status": [200], "json": [{ "pointer": "/id", "type": "string" }, { "pointer": "/status", "equals": "paid" }] }
}
```

## S3 — Reader B must not open Reader A's order

```navsentry-step
{
  "id": "S3", "action": "http", "actor": "reader_b", "object_owner": "reader_a",
  "request": { "method": "GET", "path": "/api/orders/{{orderA}}", "accept": "json" },
  "expect": { "access": "denied", "deny_status": [403, 404] }
}
```

## S4 — Reader A profile (positive control)

```navsentry-step
{
  "id": "S4", "action": "http", "actor": "reader_a",
  "request": { "method": "GET", "path": "/api/me", "accept": "json" },
  "expect": { "access": "allowed", "json": [{ "pointer": "/role", "type": "string" }] }
}
```

## S5 — Anonymous must not read a profile

```navsentry-step
{
  "id": "S5", "action": "http", "actor": "anonymous",
  "request": { "method": "GET", "path": "/api/me", "accept": "json" },
  "expect": { "access": "denied" }
}
```

## S6 — Admin sees stats (positive control)

```navsentry-step
{
  "id": "S6", "action": "http", "actor": "admin",
  "request": { "method": "GET", "path": "/api/admin/stats", "accept": "json" },
  "expect": { "access": "allowed", "content_type": "application/json" }
}
```

## S7 — Reader must not see admin stats

```navsentry-step
{
  "id": "S7", "action": "http", "actor": "reader_a",
  "request": { "method": "GET", "path": "/api/admin/stats", "accept": "json" },
  "expect": { "access": "denied" }
}
```
