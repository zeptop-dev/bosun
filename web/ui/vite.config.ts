import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Served by bosun at /; in dev, API calls are proxied to the Go server.
export default defineConfig({
  plugins: [react()],
  base: '/',
  server: {
    port: 5174,
    proxy: { '/api': 'http://127.0.0.1:2053', '/sub': 'http://127.0.0.1:2053' },
  },
  build: { outDir: 'dist', emptyOutDir: false },
})
