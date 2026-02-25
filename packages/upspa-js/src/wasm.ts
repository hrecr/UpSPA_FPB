import * as wasm from '../wasm-pkg/upspa_wasm.js';
const initFn: unknown = (wasm as any).init;
let initPromise: Promise<typeof wasm> | null = null;
export async function loadUpspaWasm(): Promise<typeof wasm> {
  if (!initPromise) {
    initPromise = (async () => {
      if (typeof initFn === 'function') {
        await (initFn as any)();
      }
      return wasm;
    })();
  }

  return initPromise;
}
