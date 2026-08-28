import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
  },
  server: {
    port: 5730,
    strictPort: true,
    proxy: {
      '/api': 'http://127.0.0.1:8787',
    },
  },
  preview: {
    port: 5730,
    strictPort: true,
  },
  build: {
    assetsInlineLimit: 0,
    sourcemap: false,
    rollupOptions: {
      output: {
        assetFileNames: 'assets/admin-[hash:8][extname]',
        chunkFileNames: 'assets/admin-[hash:8].js',
        entryFileNames: 'assets/admin-[hash:8].js',
        hashCharacters: 'hex',
        manualChunks(id) {
          if (id.includes('/@cloudflare/kumo/')) return 'kumo'
          if (id.includes('/@phosphor-icons/')) return 'icons'
          if (id.includes('/@tanstack/')) return 'router'
          if (id.includes('/react-dom/') || id.includes('/react/')) return 'react'
          return undefined
        },
      },
    },
  },
})
