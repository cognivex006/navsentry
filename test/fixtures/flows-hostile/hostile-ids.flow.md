# Hostile extracted values

```navsentry-flow
{
  "flow": "1", "id": "hostile-ids", "title": "Target-controlled values cannot steer requests",
  "story": "Values extracted from a response that are unsafe for a URL are refused before any request.",
  "actors": ["anonymous"], "review": { "status": "draft" }
}
```

## S1 — Read values

```navsentry-step
{ "id": "S1", "action": "http", "actor": "anonymous",
  "request": { "method": "GET", "path": "/api/hostile-ids", "accept": "json" },
  "expect": { "status": [200] },
  "extract": { "traversal": { "from": "json", "pointer": "/traversal" }, "encoded": { "from": "json", "pointer": "/encoded" }, "long": { "from": "json", "pointer": "/long" }, "absolute": { "from": "json", "pointer": "/absolute" }, "ok": { "from": "json", "pointer": "/ok" } } }
```

## S2 — Traversal

```navsentry-step
{ "id": "S2", "action": "http", "actor": "anonymous", "request": { "method": "GET", "path": "/api/orders/{{traversal}}" }, "expect": { "status": "4xx" } }
```

## S3 — Encoded

```navsentry-step
{ "id": "S3", "action": "http", "actor": "anonymous", "request": { "method": "GET", "path": "/api/orders/{{encoded}}" }, "expect": { "status": "4xx" } }
```

## S4 — Long

```navsentry-step
{ "id": "S4", "action": "http", "actor": "anonymous", "request": { "method": "GET", "path": "/api/orders/{{long}}" }, "expect": { "status": "4xx" } }
```

## S5 — Absolute URL

```navsentry-step
{ "id": "S5", "action": "http", "actor": "anonymous", "request": { "method": "GET", "path": "/{{absolute}}" }, "expect": { "status": "4xx" } }
```

## S6 — Safe value into a path the manifest denies at runtime

```navsentry-step
{ "id": "S6", "action": "http", "actor": "anonymous", "request": { "method": "GET", "path": "/api/orders/{{ok}}" }, "expect": { "status": "4xx" } }
```
