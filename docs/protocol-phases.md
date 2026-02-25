# UpSPA Protocol Phases (End-to-End)

This document is the **“what actually happens on the wire”** view of UpSPA: which component does what, which messages move where, and what state gets created/updated.

UpSPA has three parties:

- **User device** (browser extension + local client logic)
- **Storage Providers (SPs)**: hold per-user encrypted blobs + TOPRF shares
- **Login Servers (LSs)**: the websites you log into (can be *unmodified* in a real deployment; for testing we provide a reference LS API)

The protocol is organized into **phases Π0…Π5**, matching the paper and the OpenAPI specs.

---

## Conventions used everywhere

### Encoding

- All binary fields that cross JSON APIs are encoded as **base64url, no padding** ("URL_SAFE_NO_PAD").
- Servers SHOULD **canonicalize** base64 inputs (decode then re-encode) so different textual encodings of the same bytes don’t create duplicate keys.

### Fixed sizes (reference implementation)

These constants are used by the reference code and OpenAPI schemas:

- `NONCE_LEN = 24` (XChaCha20 nonce)
- `TAG_LEN   = 16` (Poly1305 tag)
- Ed25519 public key: `32` bytes
- Ed25519 signature: `64` bytes
- Ristretto255 compressed point: `32` bytes
- Ristretto255 scalar share: `32` bytes

`CtBlob` is the common encrypted container:

- `CtBlob := { nonce(24), ct(variable), tag(16) }`

Concrete contexts:

- **cid** (CipherId): `ct` is **96 bytes** in the reference implementation
- **cj** (per-LS record): `ct` is **40 bytes** in the reference implementation

(Those lengths are encoded in code constants and mirrored in the OpenAPI docs.)

### Integer byte order

Whenever we serialize integers into a signature message, we use **little-endian**:

- `timestamp: u64` → 8 bytes LE
- `sp_id: u32` → 4 bytes LE

---

## Phase map

- **Π0** — Setup / enrollment (user picks password; creates SP state)
- **Π1** — Setup upload to SPs (store `cid`, `k_i`, `sig_pk`)
- **Π2** — Login / authentication (threshold TOPRF to recover the password-state key)
- **Π3** — Record creation for an LS (store encrypted per-LS secret at SP)
- **Π4** — Record fetch/update during normal operations
- **Π5** — Master password update (rotate TOPRF shares + re-encrypt `cid`)

---

## Π0–Π1: Setup (enrollment) and provisioning to SPs

### Goal

Bind a user’s master password to:

1) a **password-state key** (derived from TOPRF)
2) a per-user encrypted blob (**cid**) that contains what the client needs later (e.g., signing key material)
3) per-SP TOPRF shares (**k_i**) stored at SPs

### What the client does

1) Generate identifiers:
   - `uid` (raw bytes) → sent as `uid_b64`
2) Generate Ed25519 signing keypair:
   - keep `sig_sk` local inside `cid` plaintext
   - upload `sig_pk` to each SP (`sig_pk_b64`)
3) Run TOPRF share generation:
   - create threshold shares `(k_i)` across `nsp` providers with threshold `tsp`
4) Encrypt the cipher-id plaintext:
   - derive password-state key via TOPRF finalize
   - build AAD from `uid` (the AAD binds ciphertext to the user)
   - compute `cid = XChaCha20-Poly1305(password_state_key, aad, cipherid_pt)`

### What each SP stores

From **POST `/v1/setup`**:

- `uid_b64` (canonicalized)
- `sig_pk_b64` (canonicalized)
- `cid` (nonce/ct/tag)
- `k_i_b64` (TOPRF share for this SP)

SP response is `201 Created` (or `200 OK` if idempotent).

### State produced

- Client keeps locally:
  - `uid` (raw)
  - `cid` (encrypted)
  - SP list (`sp_id` + URLs)
- SP persists:
  - setup record (uid → {sig_pk, cid, k_i, last_pwd_update_time})

---

## Π2: Login (threshold TOPRF recovery)

### Goal

Given only `uid` and the master password, reconstruct the password-state key and decrypt `cid`.

### What the client does

1) Blind the password-derived point:
   - `P = H1(password)`
   - pick random scalar `r`
   - `blinded = r * P`
2) Send `blinded` to multiple SPs:
   - **POST `/v1/toprf/eval`** with `{ uid_b64, blinded_b64 }`
3) Collect responses from **≥ tsp** SPs:
   - each SP returns `y_i = k_i * blinded` as `y_b64`
4) Unblind and combine:
   - `y_i' = r^{-1} * y_i`
   - combine `tsp` points to reconstruct `y = sk * P`
5) Finalize:
   - `password_state_key = H2(password, y)`
6) Decrypt cid:
   - `cipherid_pt = XChaCha20-Poly1305-OPEN(password_state_key, aad(uid), cid)`

### What the SP does

- Look up `uid` → fetch stored `k_i`
- Decode `blinded_b64` → ristretto point
- Compute `y_i = blinded * k_i`
- Return `{ sp_id, y_b64 }`

### State produced

- Client obtains `password_state_key` and plaintext `cipherid_pt` in-memory.
- Nothing on SP changes in Π2.

---

## Π3: Record creation (per-LS state)

### Goal

Create LS-specific secrets and store them encrypted at an SP.

A record is indexed by:

- `suid = H(uid, ls_id, …)` (site-specific uid) → sent as `suid_b64`

### What the client does

1) Generate per-LS secret(s), e.g. a random seed.
2) Derive encryption key(s) from `password_state_key`.
3) Encrypt into a `cj` blob:
   - `cj = XChaCha20-Poly1305(key, aad(suid), plaintext)`
4) Store at an SP:
   - **POST `/v1/records`** with `{ suid_b64, cj }`

### What the SP does

- Create the record if it doesn’t exist.

### State produced

- SP persists: `suid → cj`.

---

## Π4: Record fetch/update

### Goal

Read or update the per-LS secret.

### APIs

- Fetch: **GET `/v1/records/{suid_b64}`**
- Update: **PUT `/v1/records/{suid_b64}`**

### What the client does

- Fetch `cj`, decrypt using keys derived from the recovered password-state key.
- If updating, re-encrypt and PUT.

---

## Π5: Master password update

### Goal

Rotate the user’s master password **without losing access**:

- generate new TOPRF master secret + shares
- derive new password-state key
- re-encrypt `cid` under the new key
- send each SP its new share `k_i_new`

### What the client signs

Each SP update request is authenticated by an Ed25519 signature using the signing key inside `cipherid_pt`.

Signature message bytes (reference impl):

```
msg = cid_new.nonce (24)
    || cid_new.ct    (96)
    || cid_new.tag   (16)
    || k_i_new       (32)
    || timestamp_le  (8)
    || sp_id_le      (4)
```

Total: `24 + 96 + 16 + 32 + 8 + 4 = 180` bytes.

### What the client does

1) Decrypt old `cid` using old password-state key.
2) Generate new TOPRF shares `(k_i_new)`.
3) Derive new password-state key and re-encrypt `cid_new`.
4) For each SP, send **POST `/v1/password-update`** with:

- `uid_b64`
- `sp_id`
- `timestamp`
- `sig_b64`
- `cid_new`
- `k_i_new_b64`

### What each SP does

1) Fetch stored `sig_pk` for `uid`.
2) Rebuild the exact signature message bytes.
3) Verify Ed25519 signature.
4) If configured, enforce monotonic timestamp to prevent replay.
5) Update stored `(cid, k_i, last_pwd_update_time)`.

---

## Where this lives in the project skeleton

This doc is protocol-focused, but you’ll want the code map:

- **Rust client core (protocol + crypto primitives):** `crates/upspa-core/`
- **WASM bindings (browser-friendly):** `crates/upspa-wasm/`
- **TypeScript client wrapper:** `packages/upspa-js/`
- **Browser extension:** `packages/extension/`
- **SP reference server (Go):** `services/storage-provider-go/`
- **LS reference server:** `services/login-server-*/` (language varies by implementation)

If you are implementing SP/LS independently, the **source of truth for wire fields** is:

- `docs/openapi/sp.yaml`
- `docs/openapi/ls.yaml`

---

## Storage Provider traceability map (implementation guide)

This section maps protocol steps to the Storage Provider (SP) API endpoints and to the Go file layout (`services/storage-provider-go/`). The purpose is to make it obvious where each protocol invariant must be enforced.

### Π1 — Setup

**API:**

- `POST /v1/setup`
- `GET  /v1/setup/{uid}` (optional helper endpoint; useful for debugging and test vectors)

**Go files:**

- `internal/api/setup.go`
- `internal/api/setup_get.go`
- `internal/db/queries.go` (`SetupInsert`, `SetupGet`)

**Invariants enforced at the SP:**

- Base64 canonicalization on all stored keys.
- Exact-length checks on:
  - Ed25519 public key bytes (32)
  - nonce (24) and tag (16)
  - ciphertext length (protocol-specific)
  - TOPRF scalar share `k_i` (32)
- Idempotency policy is consistent (either “already exists → 200” or “differs → 409”).

---

### Π2/Π3/Π4 — Normal login flow (SP involvement)

The SP does not participate in LS-side checks, but it does provide:

**API:**

- `POST /v1/toprf/eval`

**Go files:**

- `internal/api/toprf.go`
- `internal/crypto/ristretto.go`
- `internal/db/queries.go` (`ShareGetForUser`)

**Invariants:**

- `blinded_b64` decodes to a *canonical* Ristretto point encoding.
- The user must exist (`uid` lookup).
- Scalar multiplication must be correct: `y_i = blinded * k_i`.
- The response point encoding must be canonical.

---

### Record storage (opaque LS records)

**API:**

- `POST /v1/records`
- `GET /v1/records/{suid}`
- `PUT /v1/records/{suid}`
- `DELETE /v1/records/{suid}`

**Go files:**

- `internal/api/records.go`
- `internal/db/queries.go` (`RecordInsert`, `RecordGet`, `RecordUpdate`, `RecordDelete`)

**Invariants:**

- The SP never attempts to interpret or decrypt `cj`.
- Uniqueness is enforced on `suid`.
- Correct status codes:
  - create duplicate → 409
  - get/update/delete missing → 404

---

### Π5 — Password update (SP involvement)

**API:**

- `POST /v1/password-update`

**Go files:**

- `internal/api/pwd_update.go`
- `internal/crypto/ed25519.go`
- `internal/db/queries.go` (`SetupUpdateAfterPwdUpdate`, plus a read of current timestamp)

**Invariants:**

- The signature message must be rebuilt byte-for-byte per the protocol spec.
- Ed25519 signature verification must succeed.
- Timestamp must be monotonic (`timestamp_new > last_pwd_update_time`) to block replay.
- Updates of `cid`, `k_i`, and `last_pwd_update_time` must be atomic (transaction).

---

## Testing guidance (how to prove correctness)

The fastest path to confidence is a layered test strategy:

1) **Unit tests** (`internal/crypto/*_test.go`)
   - canonical base64 behavior
   - ristretto decode/encode roundtrip and invalid encoding rejection
   - scalar decode rejection for non-canonical scalars
   - Ed25519 verification success/failure

2) **DB integration tests** (`internal/db/*_test.go`)
   - uniqueness constraints
   - correct upsert / conflict behavior
   - password update monotonic timestamp behavior

3) **API integration tests** (`internal/api/*_test.go`)
   - status code matrix per OpenAPI
   - JSON shapes match the spec
   - negative test suite (malformed base64, wrong lengths, invalid signature, replay timestamp)

A passing “green suite” must include negative tests; otherwise the SP will interoperate in the happy path but fail in the real world.
