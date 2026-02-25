# Security Notes (Threat Model + Implementation Pitfalls)

This document is intentionally practical: it focuses on the ways UpSPA implementations usually break security in the real world.

UpSPA’s core promise is:

- the user can authenticate to an LS
- without the LS learning the master password
- and without any single SP being able to impersonate the user

…but only if the wire format, validation rules, and update logic are implemented correctly.

---

## What secrets exist, and who should know them?

### User device / client

- Master password
- Password-state key (derived via TOPRF)
- Cipher-id plaintext (contains signing key material)
- Per-LS record plaintext

### Storage Provider (SP)

- TOPRF share `k_i` (scalar)
- Encrypted blobs `cid` and `cj`
- Ed25519 verifying key `sig_pk`

SP should never learn:

- master password
- decrypted `cid` / `cj`
- LS-specific secrets

### Login Server (LS)

- Sees `vInfo` / `vInfoPrime` as “password inputs”

LS should never learn:

- master password
- TOPRF shares

---

## Correctness is security here

Most practical attacks come from mismatches and shortcuts.

### 1) Base64 canonicalization matters

If you use the raw input string as a database key, an attacker can store multiple rows for “the same bytes” by exploiting different encodings.

Rule:

- decode base64 → re-encode → use the canonical string as key

### 2) Length checks prevent “weird machine” behavior

Treat all protocol fields as fixed-length:

- Ed25519 pubkey: 32 bytes
- signature: 64 bytes
- ristretto point: 32 bytes
- scalar share: 32 bytes
- nonce: 24 bytes
- tag: 16 bytes

Reject anything else.

### 3) Canonical ristretto decoding

Not all 32-byte strings are valid compressed Ristretto points.

Rule:

- decode must reject non-canonical encodings

If you accept non-canonical encodings, you risk:

- subtle interop failures
- (in worst cases) malleability or invalid-curve-style issues

### 4) Signature message reconstruction must be byte-for-byte

Password update signatures are only meaningful if every implementation signs/verifies the **same bytes**.

Common failure modes:

- using big-endian instead of little-endian for timestamp/sp_id
- signing base64 text instead of decoded bytes
- forgetting to include one field

The exact message layout is documented in `docs/protocol-phases.md`.

### 5) Replay protection on password updates

If SP accepts old valid signed updates, an attacker who captured traffic could roll users back.

Rule:

- store `last_pwd_update_time`
- reject `timestamp <= last_pwd_update_time`

### 6) Don’t log secrets

Avoid logging:

- raw uid bytes
- blinded points
- TOPRF shares
- ciphertext blobs
- signatures

Logging should be:

- structured
- bounded
- and never contain sensitive payloads

---

## Operational hardening recommendations

These aren’t strictly required for the protocol, but matter in production.

### Rate limiting

- TOPRF eval endpoints can be used for DoS.
- Implement per-IP and per-uid rate limits.

### Abuse resistance

- Consider returning a uniform error for “unknown uid” vs “bad encoding” if user enumeration is a concern.

### Secure storage

- SP DB contains `k_i` (high-value). Protect it like a credential database.
- Encrypt-at-rest and strict access controls are strongly recommended.

### Transport security

- Always use HTTPS/TLS.
- Consider certificate pinning in the extension for controlled environments.

---

## Security testing checklist

Before you consider an SP implementation “done,” verify:

- [ ] Invalid base64 rejected
- [ ] Wrong lengths rejected
- [ ] Non-canonical ristretto points rejected
- [ ] TOPRF eval for unknown uid rejected
- [ ] Password update rejects invalid signatures
- [ ] Password update rejects replay timestamps
- [ ] Records API enforces create vs update semantics

---

## External references (recommended reading)

This project leans on well-studied primitives. The goal of this section is to provide safe “north star” references so implementation work does not drift into home‑rolled crypto.

### Encodings and wire formats

- RFC 4648 — Base64 and base64url encodings (especially “URL and Filename safe alphabet” and padding rules): https://www.rfc-editor.org/rfc/rfc4648

### Signatures

- RFC 8032 — Ed25519 signature scheme definition and test vectors: https://www.rfc-editor.org/rfc/rfc8032
- Go `crypto/ed25519` package docs (verification API): https://pkg.go.dev/crypto/ed25519

### Ristretto and OPRF background

- Ristretto group design (canonical encoding rules matter for invalid-point attacks): https://ristretto.group/
- RFC 9497 — Oblivious Pseudorandom Functions (OPRF) (background for blinding/unblinding and “why this exists”): https://www.rfc-editor.org/rfc/rfc9497

### Web service hardening

- OWASP Cheat Sheet Series (logging, transport security, and general web hardening): https://cheatsheetseries.owasp.org/

---

## Implementation safety checklist (Storage Provider focus)

This checklist is intentionally practical. It is meant to be used during code review.

### Input handling

- Request bodies have size limits.
- Every base64 field:
  - is decoded
  - checked for correct byte length
  - re-encoded (canonical form) before storage / comparison

### Cryptographic operations

- Signature verification uses a standard Ed25519 implementation (Go’s `crypto/ed25519`).
- Ristretto point parsing rejects non-canonical encodings (do not “accept and normalize”).
- Scalar decoding rejects non-canonical encodings (no modulo reduction on decode).

### Database semantics

- Uniqueness constraints exist for:
  - `uid` in the setup table
  - `suid` in the records table
- Password updates are atomic (transaction):
  - update `cid`, `k_i`, and `last_pwd_update_time` together
- Replay protection is enforced with a monotonic timestamp.

### Operational hygiene

- Logs include request IDs.
- Logs do not include sensitive values (uids, points, scalars, ciphertext blobs).
- Errors returned to clients are consistent and do not leak internals.
