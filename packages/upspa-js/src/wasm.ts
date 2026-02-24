import initWasm, * as wasm from '../wasm-pkg/upspa_wasm.js';
let initPromise: Promise<typeof wasm> | null = null;

export async function loadUpspaWasm(): Promise<typeof wasm> {
  if (!initPromise) {
    initPromise = (async () => {
      // wasm-pack bundler output figures out the .wasm URL via import.meta.url.
      await initWasm();
      return wasm;
    })();
  }
  return initPromise;
}
