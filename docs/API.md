# opaq REST API

Plain JSON over HTTP. Base URL: `<server>/api/v1` (e.g. `https://opaq.example.com/api/v1`).

The server itself terminates plain HTTP; put TLS in front of it (Caddy, nginx, Fly, etc.). All examples use HTTPS.

## Authentication

Every endpoint except `/healthz` requires a bearer token:

```
Authorization: Bearer opaq_<64 hex chars>
```

Failures:
- `401 Unauthorized` — missing, malformed, revoked, or expired key.
- `403 Forbidden` — key valid but role insufficient for the operation.

Roles (global, no path-scoping):

| Role     | Read secrets | Write secrets | Manage principals |
|----------|:-:|:-:|:-:|
| reader   | ✓ |   |   |
| writer   | ✓ | ✓ |   |
| admin    | ✓ | ✓ | ✓ |

## Errors

Every 4xx/5xx response has the same shape:

```json
{ "error": "human-readable message" }
```

Common codes: `400` (validation), `401` (auth), `403` (role), `404` (not found), `409` (conflict), `500` (server).

## Endpoints

### Health

```
GET /healthz                        (no auth)
→ 200  { "ok": true }
```

### Identity

```
GET /api/v1/me
→ 200  {
         "principal": {
           "id": 1,
           "name": "root",
           "role": "admin",
           "expires_at": null
         }
       }
```

### Principals (admin only, except where noted)

#### Upsert (create or update by name)

Looks up an active principal by `name`. If found, updates fields **without** rotating the API key. If not, creates a new principal and mints a key.

```
PUT /api/v1/principals
body: {
  "name":         "ci-bot",          // required (lookup key)
  "role":         "writer",          // optional
  "ttl_seconds":  2592000,           // optional, mutually exclusive with clear_ttl
  "clear_ttl":    false,             // optional, true clears expires_at
  "rename":       "ci-runner"        // optional, errors if name doesn't exist yet
}
→ 200 {
        "action":     "created" | "updated",
        "id":         2,
        "name":       "ci-runner",
        "role":       "writer",
        "expires_at": "...",
        "key":        "opaq_..."     // present only when action == "created"
      }
```

Constraints:
- `ttl_seconds` and `clear_ttl` are mutually exclusive.
- Demoting the last admin returns `403`.
- Renaming to an in-use active name returns `400`.
- Renaming a non-existent principal returns `404`.

#### Rotate (mint a new API key, preserve everything else)

Looks up an active principal by `name`, generates a fresh API key, replaces the stored fingerprint, and returns the new plaintext key. The principal's id, name, role, and expiry are preserved. The old key stops authenticating immediately.

**Auth:** admin (any principal), OR the principal rotating its own key (caller's authenticated `name` must equal the request `name`). Non-admins rotating other principals get `403`.

```
POST /api/v1/principals/rotate
body: { "name": "ci-bot" }
→ 200 {
        "id":         2,
        "name":       "ci-bot",
        "role":       "writer",
        "key":        "opaq_<64hex>",
        "expires_at": "..."
      }
```

`404` if no active principal exists with that name.

#### List

```
GET /api/v1/principals
→ 200 [
        {
          "id": 1, "name": "root", "role": "admin",
          "created_at": "1745000000", "revoked_at": null, "expires_at": null
        },
        ...
      ]
```

#### Revoke

```
DELETE /api/v1/principals/{id}
→ 200 { "ok": true }
```

Refused with `403` if the target is the last active admin.

### Secrets

Path syntax mirrors the CLI: workspace / project / [env] / key, each segment matching `[a-zA-Z0-9_-]{1,64}`.

#### Set (writer)

```
PUT /api/v1/secrets/{ws}/{proj}/{key}                # project-scoped
PUT /api/v1/secrets/{ws}/{proj}/{env}/{key}          # env-scoped
body: {
  "type":  "string" | "json",        // optional, default "string"
  "value": "..."                     // required; for json, must be valid JSON text
}
→ 200 { "path": "/ws/proj/env/key", "type": "string" }
```

#### Get (reader)

```
GET /api/v1/secrets/{ws}/{proj}/{key}
GET /api/v1/secrets/{ws}/{proj}/{env}/{key}
→ 200 { "path": "/ws/proj/env/key", "type": "string", "value": "sk_live_xxx" }
```

There is **no inheritance**. Looking up an env-scoped path does not fall back to the project-scoped key of the same name.

#### Delete (writer)

```
DELETE /api/v1/secrets/{ws}/{proj}/{key}
DELETE /api/v1/secrets/{ws}/{proj}/{env}/{key}
→ 200 { "ok": true }
```

### Listing (reader)

```
GET /api/v1/list/{ws}/{proj}                         # project-scoped + every env
GET /api/v1/list/{ws}/{proj}/{env}                   # env-scoped only
→ 200 [
        { "path": "/ws/proj/env/key", "type": "string" },
        { "path": "/ws/proj/key2",    "type": "json"   },
        ...
      ]
```

Add `?values=true` to fetch each entry's value in the same response (single round trip; no per-key `GET /secrets/...` follow-ups):

```
GET /api/v1/list/{ws}/{proj}?values=true
GET /api/v1/list/{ws}/{proj}/{env}?values=true
→ 200 [
        { "path": "/ws/proj/env/key", "type": "string", "value": "sk_live_xxx" },
        ...
      ]
```

The bulk read is logged once in the audit log (`action=list_with_values`), not per-secret. To assemble a `KEY=VAL` env stream with env-scoped overrides winning, the CLI calls the project-list endpoint with `?values=true` and applies the merge client-side. See `opaq env` and `src/bin/cli/main.rs`.

## Examples

```bash
# whoami
curl -fsSL https://opaq.example.com/api/v1/me \
  -H "Authorization: Bearer $OPAQ_KEY"

# upsert a principal
curl -fsSL -X PUT https://opaq.example.com/api/v1/principals \
  -H "Authorization: Bearer $OPAQ_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"ci-bot","role":"writer","ttl_seconds":2592000}'

# rotate an API key
curl -fsSL -X POST https://opaq.example.com/api/v1/principals/rotate \
  -H "Authorization: Bearer $OPAQ_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"ci-bot"}'

# write a secret
curl -fsSL -X PUT https://opaq.example.com/api/v1/secrets/acme/api/prod/STRIPE_KEY \
  -H "Authorization: Bearer $OPAQ_KEY" \
  -H "Content-Type: application/json" \
  -d '{"type":"string","value":"sk_live_xxx"}'

# read it back
curl -fsSL https://opaq.example.com/api/v1/secrets/acme/api/prod/STRIPE_KEY \
  -H "Authorization: Bearer $OPAQ_KEY"
```
