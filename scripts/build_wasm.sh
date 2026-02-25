set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack not found. Install it: https://rustwasm.github.io/wasm-pack/installer/" >&2
  exit 1
fi

echo "Building upspa-wasm (bundler target)…"

cd "$ROOT_DIR"

wasm-pack build crates/upspa-wasm \
  --release \
  --target bundler \
  --out-dir "$ROOT_DIR/packages/upspa-js/wasm-pkg" \
  --out-name upspa_wasm

echo "WASM package written to packages/upspa-js/wasm-pkg"
