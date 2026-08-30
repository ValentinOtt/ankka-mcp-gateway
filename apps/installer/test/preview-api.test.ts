import { createServer } from 'node:http'
import * as v from 'valibot'
import { installerPreviewApi } from '../preview/mock-api'

async function preview() {
  const middleware = installerPreviewApi()
  const server = createServer((request, response) => {
    middleware(request, response, () => {
      response.statusCode = 204
      response.end()
    })
  })
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const { port } = v.parse(v.object({ port: v.number() }), server.address())
  const origin = `http://127.0.0.1:${port}`
  return {
    request: (path: string, method = 'GET', referer = '/') => fetch(`${origin}${path}`, {
      method,
      headers: { referer: `${origin}${referer}` },
      redirect: 'error',
    }),
    close: () => new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve())
      server.closeAllConnections()
    }),
  }
}

describe('synthetic installer preview session', () => {
  it('retains configuration and its plan through status refreshes and client-side routes', async () => {
    const api = await preview()
    try {
      expect(await (await api.request('/api/session', 'GET', '/gateway?preview=connected')).json()).toMatchObject({ selection: null, plan: null })
      const configured = await (await api.request('/api/selection', 'PUT', '/gateway?preview=connected')).json()
      expect(configured).toMatchObject({ plan: null, capabilities: { plan: true } })
      expect(await (await api.request('/api/session', 'GET', '/review')).json()).toEqual(configured)
      const planned = await (await api.request('/api/plan', 'POST', '/review')).json()
      expect(planned).toMatchObject({ plan: { planId: 'plan-example-preview', writesPerformed: false } })
      expect(await (await api.request('/api/session', 'GET', '/review')).json()).toEqual(planned)
      expect(await (await api.request('/api/session', 'GET', '/gateway?preview=connected')).json()).toEqual(planned)
      expect(await (await api.request('/api/session', 'GET', '/deploy')).json()).toEqual(planned)
    } finally {
      await api.close()
    }
  })

  it('explicit fixture navigation resets retained state, including a repeated fixture', async () => {
    const api = await preview()
    try {
      await api.request('/gateway?preview=connected')
      await api.request('/api/selection', 'PUT', '/gateway?preview=connected')
      await api.request('/api/plan', 'POST', '/review')
      await api.request('/gateway?preview=connected')
      expect(await (await api.request('/api/session', 'GET', '/gateway?preview=connected')).json()).toMatchObject({ selection: null, plan: null })
      expect(await (await api.request('/api/session', 'GET', '/result?preview=failed')).json()).toMatchObject({ deployment: { status: 'failed' } })
      expect(await (await api.request('/api/session', 'GET', '/?preview=start')).json()).toMatchObject({ selection: null, plan: null, deployment: null })
    } finally {
      await api.close()
    }
  })

  it('retains a synthetic removal review across refreshes without executing it', async () => {
    const api = await preview()
    try {
      await api.request('/api/session', 'GET', '/result?preview=success')
      const planned = await (await api.request('/api/uninstall/plan', 'POST', '/result?preview=success')).json()
      expect(planned).toMatchObject({ removal: { status: 'planned', plan: { writesPerformed: false } } })
      expect(await (await api.request('/api/session', 'GET', '/result')).json()).toEqual(planned)
      expect((await api.request('/api/uninstall', 'POST', '/result')).status).toBe(409)
      expect(await (await api.request('/api/session', 'GET', '/result')).json()).toEqual(planned)
    } finally {
      await api.close()
    }
  })

  it('consent entrypoints stay unavailable and never imply completed discovery or installation', async () => {
    const api = await preview()
    try {
      const before = await (await api.request('/api/session')).json()
      for (const endpoint of ['/api/discovery', '/api/deploy', '/api/uninstall']) {
        const response = await api.request(endpoint, 'POST')
        expect(response.status).toBe(409)
        expect(await response.json()).toEqual({ schemaVersion: 1, code: 'preview_authorization_unavailable' })
        expect(await (await api.request('/api/session')).json()).toEqual(before)
      }
      expect(await (await api.request('/api/discovery')).json()).toMatchObject({ status: 'not_started', targets: [], grantRevocation: null })
      expect(await (await api.request('/api/discovery', 'GET', '/gateway?preview=connected')).json()).toMatchObject({ status: 'ready', grantRevocation: 'confirmed' })
    } finally {
      await api.close()
    }
  })
})
