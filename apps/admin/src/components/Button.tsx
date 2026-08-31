import { Button as KumoButton } from '@cloudflare/kumo'
import type { ComponentProps } from 'react'

export function Button(props: ComponentProps<typeof KumoButton>) {
  return (
    <KumoButton
      {...props}
      // Keep Kumo's interaction behavior; our shared styles own the visual variants.
      variant="ghost"
      data-gateway-variant={props.variant ?? 'secondary'}
      className={`gateway-button pressable ${props.className ?? ''}`}
    />
  )
}
