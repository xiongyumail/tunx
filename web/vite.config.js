import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// The build lands in internal/hub/webui/dist, which tunx-hub embeds with
// go:embed. `npm run dev` proxies /api to a local tunx-hub.
export default defineConfig({
  plugins: [vue()],
  base: '/',
  build: {
    outDir: '../internal/hub/webui/dist',
    emptyOutDir: true,
    assetsDir: 'assets',
    chunkSizeWarningLimit: 1500,
    modulePreload: { polyfill: false },
  },
  server: {
    host: '127.0.0.1',
    proxy: { '/api': 'http://127.0.0.1:8780' },
  },
})
