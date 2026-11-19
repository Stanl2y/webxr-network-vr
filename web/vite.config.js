import { defineConfig } from 'vite';

// `npm run dev` proxies /ws to a local agent on :8080 (falls back to demo mode if absent).
export default defineConfig({
  base: './',
  server: { proxy: { '/ws': { target: 'ws://localhost:8080', ws: true } } },
  build: { outDir: 'dist', chunkSizeWarningLimit: 1024 },
});
