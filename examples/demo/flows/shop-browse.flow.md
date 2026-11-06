# Visitor browses the demo shop

A visitor opens the home page, goes to the product list and opens one product.
Run it with `--engine playwright` so the clicks happen in NavSentry's browser.

```navsentry-flow
{
  "flow": "1",
  "id": "shop-browse",
  "title": "Visitor browses products",
  "story": "A visitor opens the shop, goes to Products and opens the rice cooker.",
  "actors": [
    "anonymous"
  ],
  "tags": [
    "demo",
    "e2e"
  ],
  "review": {
    "status": "approved",
    "approved_by": "demo-owner",
    "approved_at": "2026-11-06",
    "reference": "DEMO-1",
    "content_sha256": "f2f5ee8cf046cbe704af0aee2b3c0a291168521c27c98145c002dcfe3c00158f"
  },
  "provenance": {
    "kind": "human",
    "sources": [
      "demo"
    ]
  }
}
```

## S1 — Home page loads

```navsentry-step
{ "id": "S1", "action": "navigate", "actor": "anonymous",
  "request": { "method": "GET", "path": "/" },
  "expect": { "status": [200], "content_type": "text/html", "text_present": ["Demo shop"] } }
```

## S2 — Open the product list

```navsentry-step
{ "id": "S2", "action": "click", "actor": "anonymous", "target": { "role": "link", "name": "Browse products" } }
```

## S3 — Products are listed

```navsentry-step
{ "id": "S3", "action": "see", "actor": "anonymous", "target": { "text": "Rice cooker — 1290 THB" } }
```

## S4 — Open one product

```navsentry-step
{ "id": "S4", "action": "click", "actor": "anonymous", "target": { "role": "link", "name": "Rice cooker — 1290 THB" } }
```

## S5 — Price is shown

```navsentry-step
{ "id": "S5", "action": "see", "actor": "anonymous", "target": { "text": "Price: 1290 THB" } }
```
