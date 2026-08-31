import { Dialog } from '@cloudflare/kumo/primitives/dialog'
import { Plus } from '@phosphor-icons/react'
import { type FormEvent, useEffect, useId, useRef, useState } from 'react'
import type { TeamMember } from '../api'
import { Button } from './Button'

const EMAIL = /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u

interface AddUserDialogProps {
  members: TeamMember[]
  disabled: boolean
  onAdd(email: string): void
}

export function AddUserDialog({ members, disabled, onAdd }: AddUserDialogProps) {
  const [open, setOpen] = useState(false)
  const [email, setEmail] = useState('')
  const [error, setError] = useState<string | null>(null)
  const input = useRef<HTMLInputElement>(null)
  const inputId = useId()
  const errorId = useId()
  useEffect(() => {
    if (disabled) setOpen(false)
  }, [disabled])

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (disabled) return
    const normalized = email.trim().toLowerCase()
    if (normalized.length > 254 || !EMAIL.test(normalized)) {
      setError('Enter a valid email address, up to 254 characters.')
      return
    }
    if (members.some((member) => member.email.toLowerCase() === normalized)) {
      setError('This user is already in your team.')
      return
    }
    onAdd(normalized)
    setOpen(false)
  }

  return (
    <Dialog.Root open={open} onOpenChange={(nextOpen) => { setOpen(nextOpen); setEmail(''); setError(null) }}>
      <Dialog.Trigger disabled={disabled} render={<Button variant="secondary" />}>
        <Plus size={16} aria-hidden="true" /> Add user
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Backdrop className="fixed inset-0 z-40 bg-black/65" />
        <Dialog.Popup initialFocus={input} className="fixed top-1/2 left-1/2 z-50 max-h-[calc(100dvh-2rem)] w-[calc(100%-2rem)] max-w-md -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-xl border border-kumo-line bg-kumo-overlay p-6 text-kumo-default shadow-xl">
          <Dialog.Title className="text-lg font-semibold text-kumo-strong">Add user</Dialog.Title>
          <Dialog.Description className="mt-2 text-sm text-kumo-subtle">New users start with no sources.</Dialog.Description>
          <form onSubmit={submit} className="mt-5">
            <label htmlFor={inputId} className="block text-sm font-medium">Email</label>
            <input ref={input} id={inputId} type="email" autoComplete="off" required maxLength={254} className="text-input mt-2 w-full" placeholder="teammate@example.com" value={email} aria-invalid={Boolean(error)} aria-describedby={error ? errorId : undefined} onChange={(event) => { setEmail(event.target.value); setError(null) }} />
            {error ? <p id={errorId} role="alert" className="field-error">{error}</p> : null}
            <div className="mt-6 flex justify-end gap-2">
              <Dialog.Close render={<Button type="button" variant="secondary" />}>Cancel</Dialog.Close>
              <Button type="submit" variant="primary" disabled={disabled || !email.trim()}>Add user</Button>
            </div>
          </form>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
