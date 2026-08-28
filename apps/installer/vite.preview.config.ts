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
            window.open = function () { return null; };
            window.addEventListener('click', function (event) {
              var link = event.target.closest('a[target="_blank"]');
              if (!link) return;
              event.preventDefault();
              var notice = document.getElementById('live-notice');
              if (notice) notice.textContent = 'OAuth links are inert in the local UI preview.';
            }, true);
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
