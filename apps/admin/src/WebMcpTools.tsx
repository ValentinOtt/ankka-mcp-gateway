import { useEffect } from 'react'
import { useGateway } from './GatewayContext'
import { createGatewayWebMcpTools, registerGatewayWebMcpTools } from './webmcp'

export type { WebMcpTool } from './webmcp'

export function WebMcpTools() {
  const { api, sources, refreshAfterExternalChange } = useGateway()
  const ready = sources !== null
  const installationEnabled = sources?.installationEnabled === true

  useEffect(() => {
    const modelContext = document.modelContext
    if (!modelContext || !ready) return
    const tools = createGatewayWebMcpTools(api, installationEnabled, refreshAfterExternalChange)
    let controller = new AbortController()
    const start = () => {
      controller.abort()
      controller = new AbortController()
      void registerGatewayWebMcpTools(modelContext, tools, controller)
    }
    const stop = () => { controller.abort() }
    start()
    window.addEventListener('pagehide', stop)
    window.addEventListener('pageshow', start)
    return () => {
      stop()
      window.removeEventListener('pagehide', stop)
      window.removeEventListener('pageshow', start)
    }
  }, [api, ready, installationEnabled, refreshAfterExternalChange])

  return null
}
