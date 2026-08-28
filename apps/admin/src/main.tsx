import { Toasty, TooltipProvider } from '@cloudflare/kumo'
import { RouterProvider } from '@tanstack/react-router'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { GatewayProvider } from './GatewayContext'
import { createPreviewGatewayAdminApi } from './preview-api'
import { router } from './router'
import { WebMcpTools } from './WebMcpTools'
import './styles.css'

const root = document.getElementById('root')
if (!root) throw new Error('Missing root element')
const previewApi = createPreviewGatewayAdminApi()
const application = (
  <>
    <WebMcpTools />
    <RouterProvider router={router} />
  </>
)
const gateway = previewApi === undefined
  ? <GatewayProvider>{application}</GatewayProvider>
  : <GatewayProvider api={previewApi}>{application}</GatewayProvider>

createRoot(root).render(
  <StrictMode>
    <TooltipProvider>
      <Toasty>
        {gateway}
      </Toasty>
    </TooltipProvider>
  </StrictMode>,
)
