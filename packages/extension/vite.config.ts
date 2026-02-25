if (typeof (globalThis as any).File === "undefined") {
  (globalThis as any).File = class File {};
}

const { defineConfig } = await import("vite");
const { crx } = await import("@crxjs/vite-plugin");
const { default: wasm } = await import("vite-plugin-wasm");
const manifest = (await import("./src/manifest")).default;

export default defineConfig({
  plugins: [wasm(), crx({ manifest })],
  build: {
    target: "es2022",
  },
});