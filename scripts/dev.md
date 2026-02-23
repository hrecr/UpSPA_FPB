# Local development notes

## Prereqs

* Rust stable + cargo
* wasm-pack
* Node.js 18+ (this repo works with modern Node)

## Build WASM

```bash
./scripts/build_wasm.sh
```

## Build TS library

```bash
cd packages/upspa-js
npm install
npm run build
```

## Build extension

```bash
cd packages/extension
npm install
npm run build
```

Load in Chrome:

* `chrome://extensions` → Developer mode → Load unpacked → `packages/extension/dist`

## Run a local SP server (Go reference)

This repo includes a reference SP server at `services/storage-provider-go`.

You’ll need a Postgres DB. Example with Docker:

```bash
docker run --rm -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:16
```

Then in another terminal:

```bash
export DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable'
export SP_ID='1'
export ENFORCE_PWD_UPDATE_TIME='true'

cd services/storage-provider-go

go run ./cmd/sp
```
