# APIs (Wire Format + Invariants)

This document explains the **exact API payload shapes**, **encoding rules**, and the important **invariants**.

---

## Global encoding rules

### Base64

All binary fields are encoded as:

- **base64url**
- **no padding**

Practical consequences:

- Server should **canonicalize** (`decode` → `encode`) before:
  - using IDs as DB keys
  - comparing values
  - logging / returning back

### CtBlob

Many fields are encrypted blobs represented as:

```json
{
  "nonce": "base64url(24 bytes)",
  "ct":    "base64url(variable bytes)",
  "tag":   "base64url(16 bytes)"
}
```

The `ct` length depends on the context (e.g. `cid` vs `cj`).

### Integers

- `sp_id` is an unsigned 32-bit integer.
- `timestamp` is an unsigned 64-bit integer.

In JSON the OpenAPI spec marks them as `uint32/uint64`. For JavaScript / TypeScript:

- JSON does not support BigInt natively.
- If you keep `timestamp` in **seconds** (or even milliseconds for many years), it stays under `2^53-1` and can be safely represented as a JS `number`.
- If you ever need true full-range `u64`, represent it as a **string** in JSON (but then update OpenAPI + clients accordingly).

The reference skeleton uses `timestamp` as a JS `number` and a Rust `u64`.

---

## Storage Provider (SP) API

Base URL examples (deployment-specific):

- `https://sp.example.com`

### GET `/v1/health`

Health probe.

**Response 200**

```json
{ "ok": true }
```

---

### POST `/v1/setup`  (Π1)

Provision per-user setup material.

**Request** (`SetupRequest`)

```json
{
  "uid_b64": "...",
  "sig_pk_b64": "...",
  "cid": { "nonce": "...", "ct": "...", "tag": "..." },
  "k_i_b64": "..."
}
```

Semantic meaning:

- `uid_b64`: user identifier (opaque bytes)
- `sig_pk_b64`: Ed25519 verifying key for password updates
- `cid`: encrypted cipher-id blob
- `k_i_b64`: this SP’s TOPRF scalar share

**Responses**

- `201 Created`: first-time setup inserted
- `200 OK`: idempotent behavior (same uid already stored with same values)
- `409 Conflict`: setup exists but differs (policy decision)

Implementation notes:

- Prefer `INSERT ... ON CONFLICT DO NOTHING` + compare existing values if you want strict conflict detection.

---

### GET `/v1/setup/{uid_b64}`

Fetch stored setup data for a user.

**Response 200** (`SetupResponse`)

```json
{
  "uid_b64": "...",
  "sig_pk_b64": "...",
  "cid": { "nonce": "...", "ct": "...", "tag": "..." }
}
```

**Response 404** if not found.

---

### POST `/v1/toprf/eval` (Π2)

Evaluate TOPRF partial `y_i = blinded * k_i`.

**Request** (`ToprfEvalRequest`)

```json
{
  "uid_b64": "...",
  "blinded_b64": "..."
}
```

- `blinded_b64` is a compressed Ristretto point (32 bytes).

**Response 200** (`ToprfEvalResponse`)

```json
{
  "sp_id": 1,
  "y_b64": "..."
}
```

Error handling:

- `400 Bad Request` if decoding fails
- `404 Not Found` if `uid` not provisioned

Security invariants:

- Never accept non-canonical points/scalars.
- Never leak different error timing for “user exists” vs “decode fail” unless you explicitly accept that threat model.

---

### POST `/v1/records` (Π3)

Create a per-LS record.

**Request** (`RecordCreateRequest`)

```json
{
  "suid_b64": "...",
  "cj": { "nonce": "...", "ct": "...", "tag": "..." }
}
```

**Responses**

- `201 Created`
- `409 Conflict` if already exists

---

### GET `/v1/records/{suid_b64}` (Π4)

Fetch a per-LS record.

**Response 200** (`RecordResponse`)

```json
{
  "suid_b64": "...",
  "cj": { "nonce": "...", "ct": "...", "tag": "..." }
}
```

---

### PUT `/v1/records/{suid_b64}` (Π4)

Replace/update a per-LS record.

**Request** (`RecordUpdateRequest`)

```json
{ "cj": { "nonce": "...", "ct": "...", "tag": "..." } }
```

**Response 200** on success, `404` if missing.

---

### POST `/v1/password-update` (Π5)

Apply a master password update for a specific SP.

**Request** (`PasswordUpdateRequest`)

```json
{
  "uid_b64": "...",
  "sp_id": 1,
  "timestamp": 1739999999,
  "sig_b64": "...",
  "cid_new": { "nonce": "...", "ct": "...", "tag": "..." },
  "k_i_new_b64": "..."
}
```

Verification invariant (this is the #1 place people accidentally break compatibility):

- The SP must rebuild the signature message bytes *exactly* as specified in `protocol-phases.md`.
- The `sp_id` included in the signature message is the **same sp_id** field in JSON.

Replay protection:

- SP should store `last_pwd_update_time` per user.
- Reject (`409 Conflict`) when `timestamp <= last_pwd_update_time`.

---

## Reference Login Server (LS) API

The LS OpenAPI is meant for **testing** and demos.

In a real deployment, UpSPA typically runs against an unmodified LS by:

- deriving a site-specific secret
- translating it into the LS’s expected password input
- filling out the LS login form via extension automation

For automated integration tests we provide an LS API:

- `POST /register`: password = `vInfo` (base64url)
- `POST /login`: password = `vInfoPrime`
- `POST /change-password`: old=`vInfoPrime`, new=`vInfoNew`

See `docs/openapi/ls.yaml`.

---

## Practical testing tips (client ↔ API)

- Always test:
  - malformed base64
  - wrong lengths
  - wrong signature
  - replay timestamps
  - threshold behavior (`tsp-1` responses must fail)
- Prefer deterministic test vectors:
  - seed RNG
  - fixed uid/password
  - known expected CID + TOPRF outputs

The Rust `upspa-core` crate is the best place to define authoritative vectors, then mirror them in:

- Go SP tests
- TS/WASM tests

---



