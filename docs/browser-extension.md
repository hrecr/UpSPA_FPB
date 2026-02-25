# Browser Extension Architecture

This document explains what the UpSPA browser extension does at runtime, how it talks to the client protocol implementation (Rust → WASM → TS), and how it mediates between:

- the **user** (typing a password once),
- multiple **Storage Providers (SPs)**, and
- one or more **Login Servers (LSs)**.

It also contains the “this is how you actually build it without crying” notes.

---

## Components (MV3)

### Background service worker

File: `packages/extension/src/background/index.ts`

Responsibilities:

- Owns the long-lived **UpSPA client state** (as long as the MV3 service worker stays alive).
- Performs all network calls to SPs (and optionally to a reference LS for tests).
- Orchestrates protocol phases:
  - Setup (Π0–Π1)
  - TOPRF login (Π2)
  - Record create/fetch/update (Π3–Π4)
  - Password update (Π5)

The service worker is the “brain.” It does not touch page DOM.

### Content script

File: `packages/extension/src/content/index.ts`

Responsibilities:

- Runs in the context of each webpage.
- Detects:
  - login form submission
  - registration form submission
  - password change forms
- Sends messages to the background service worker with:
  - the LS origin / hostname
  - username (if required)
  - user password input (only as needed; then should be cleared)

### Popup / Options

Files:

- `packages/extension/src/popup/*`
- `packages/extension/src/options/*`

Responsibilities:

- Configure SP endpoints list
- Configure which LS domains should use UpSPA
- Show debug status (e.g., “setup done”, “connected SPs: 3/5”)

---

## Where the crypto/protocol logic lives

### Rust core

- `crates/upspa-core/` implements:
  - XChaCha20-Poly1305 encryption / decryption wrappers
  - TOPRF primitives and combination
  - signature rules for password update
  - protocol helpers

### WASM bindings

- `crates/upspa-wasm/` exposes a small ABI for the browser.

### TypeScript wrapper

- `packages/upspa-js/` provides a friendly client API (`UpspaClient`) and hides WASM details.

### Extension integration

- Extension depends on `upspa-js` and calls it from background.

---

## Runtime flow (what happens on a real login)

### 1) User visits LS and submits login form

- Content script intercepts the submit.
- It sends `{ origin, username?, password }` to background.

### 2) Background performs TOPRF against SPs (Π2)

- Load WASM (once) and create an `UpspaClient`.
- Compute the blinded point from password.
- Call `/v1/toprf/eval` on multiple SPs.
- Combine `tsp` responses, derive `password_state_key`, decrypt `cid`.

### 3) Background derives LS-specific secret

- Derive `suid = H(uid, origin, ...)`.
- Fetch or create record `cj` from an SP.
- Decrypt `cj` and derive `vInfoPrime`.

### 4) Background returns the transformed password to content script

- Content script fills the LS password field with `vInfoPrime` (or uses it to authenticate via API in test LS).

---

## Building the extension (with WASM)

### Prerequisites

- Rust toolchain (stable)
- `wasm-pack`
- Node.js **20+ recommended**
  - Node 18 can work, but some build-time dependencies may assume the `File` global exists.
- npm with workspace support (npm 8+ is fine; npm 9+ recommended)

### Build order (important)

The extension depends on JS, and JS depends on the generated WASM package.

From repo root:

1) Build the WASM package

```bash
npm run build:wasm
```

2) Build the TS client wrapper

```bash
npm run build:js
```

3) Build the extension

```bash
npm run build:ext
```

### Why `wasm-pkg/` is often in `.gitignore`

`wasm-pkg/` is typically **generated output** from `wasm-pack build`.

The repo keeps:

- Rust source (`crates/upspa-wasm/`)

…and generates:

- `packages/upspa-js/wasm-pkg/*` (JS glue + `.wasm` binary)

That’s why it can be ignored in git: you rebuild it deterministically.

### Vite + wasm-pack: the common pitfall

If you see something like:

> "ESM integration proposal for Wasm" is not supported currently

…it usually means your wasm-pack output is using:

```js
import * as wasm from "./upspa_wasm_bg.wasm";
```

Vite does not currently accept this import style without help.

Recommended fixes (pick ONE):

1) **Build wasm-pack with `--target web`** (most straightforward)
   - Generated JS uses `fetch()` to load the `.wasm`.
   - Works well with Vite.

2) Patch the generated import to use Vite’s query helpers:
   - `./upspa_wasm_bg.wasm?url` (get URL string)
   - `./upspa_wasm_bg.wasm?init` (get init function)

3) Add a community plugin (e.g., `vite-plugin-wasm`).

The project skeleton prefers option (1) or (2) so interns don’t have to learn Vite plugin archaeology.

---

## Debugging tips

- MV3 background logs:
  - Chrome: `chrome://extensions` → your extension → “Service worker” → Inspect
- Network:
  - Look at requests to `/v1/toprf/eval`, `/v1/records/*`, `/v1/password-update`
- Crypto failures:
  - Most issues are length/encoding mismatches.
  - Always verify base64url-no-pad and fixed byte lengths first.

---

## WASM build artifacts and why `wasm-pkg/` is generated

The browser extension depends on the **WASM bindings** of the UpSPA client library.

In this repository layout, the WASM build outputs are treated as **generated artifacts**:

- `packages/upspa-wasm/` contains the package metadata and “published surface”.
- `packages/upspa-js/wasm-pkg/` contains the JavaScript + `.wasm` output produced by `wasm-pack`.

It is normal for the `wasm-pkg/` directory to appear in `.gitignore` in early-stage repos because:

- it is build-output (not hand-authored source code),
- it can be large and frequently changing,
- it is reproducible from the Rust crate + build script.

A clean build should regenerate it.

### Reference docs (WASM toolchain)

- wasm-pack (official): https://rustwasm.github.io/wasm-pack/
- Rust + WebAssembly book: https://rustwasm.github.io/docs/book/

---

## Vite and `.wasm` imports (common pitfall)

Modern Vite builds do not accept a direct ESM import like:

- `import * as wasm from "./upspa_wasm_bg.wasm"`

unless the project is configured to handle the WebAssembly integration.

If a build fails with an error like “ESM integration proposal for Wasm is not supported”, the typical fixes are:

- Use Vite’s documented query forms (`.wasm?url` or `.wasm?init`) **or**
- Use a community WebAssembly plugin.

### Reference docs (Vite)

- Vite WebAssembly guide: https://vite.dev/guide/features.html#webassembly

The goal is not to invent a custom loader; it is to use Vite’s supported mechanisms so the extension build remains reproducible.
