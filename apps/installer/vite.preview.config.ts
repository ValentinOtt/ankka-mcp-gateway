import { fileURLToPath } from 'node:url'
import { defineConfig, type Plugin } from 'vite'
import { installerPreviewApi } from './preview/mock-api'

const installerRoot = fileURLToPath(new URL('../../payload/installer', import.meta.url))

function installerPreviewPlugin(): Plugin {
  return {
    name: 'ankka-installer-preview',
    configureServer(server) {
      server.middlewares.use(installerPreviewApi())
    },
    handleHotUpdate(context) {
      if (!context.file.startsWith(installerRoot)) return
      context.server.ws.send({ type: 'full-reload' })
      return []
    },
    transformIndexHtml: {
      order: 'pre',
      handler() {
        return [{
          tag: 'script',
          injectTo: 'head-prepend',
          children: `
            document.documentElement.dataset.oauthPreview = 'inert';
          `,
        }]
      },
    },
  }
}

export default defineConfig({
  root: installerRoot,
  appType: 'spa',
  plugins: [installerPreviewPlugin()],
  server: {
    host: '127.0.0.1',
    port: 5731,
    strictPort: true,
  },
})
