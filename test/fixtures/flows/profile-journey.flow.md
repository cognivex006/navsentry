# Reader opens profile and order history

```navsentry-flow
{
  "flow": "1", "id": "profile-journey", "title": "Reader profile journey",
  "story": "A signed-in reader opens the profile page and navigates to order history; visitors are sent to login.",
  "actors": ["reader_a", "anonymous"], "login_path": "/login",
  "review": { "status": "draft" }
}
```

## S1 — Profile page loads

```navsentry-step
{ "id": "S1", "action": "navigate", "actor": "reader_a",
  "request": { "method": "GET", "path": "/app/profile" },
  "expect": { "access": "allowed", "status": [200], "content_type": "text/html", "text_present": ["Profile"] } }
```

## S2 — Open order history

```navsentry-step
{ "id": "S2", "action": "click", "actor": "reader_a", "target": { "role": "link", "name": "Orders" } }
```

## S3 — History is visible

```navsentry-step
{ "id": "S3", "action": "see", "actor": "reader_a", "target": { "text": "Order history" } }
```

## S4 — Visitor is sent to login

```navsentry-step
{ "id": "S4", "action": "navigate", "actor": "anonymous",
  "request": { "method": "GET", "path": "/app/profile" },
  "expect": { "access": "denied" } }
```
