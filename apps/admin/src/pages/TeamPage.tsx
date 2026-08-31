import { Button, Input } from '@cloudflare/kumo'
import { ArrowsClockwise, Check, Plus, ShieldCheck, Trash, X } from '@phosphor-icons/react'
import { type FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { GatewayApiError, SOURCE_ADDITION_PAUSED_MESSAGE, TEAM_MAX_PEOPLE, type Team, type TeamAction, type TeamMember } from '../api'
import { PageHeader } from '../components/PageHeader'
import { StatusPill } from '../components/StatusPill'
import { useGateway } from '../GatewayContext'
import { isGatewayUiPreview } from '../preview-api'

const ACTION_ID = /^action_[A-Za-z0-9_-]{32}$/u
const EMAIL = /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}$/u

function canonicalMembers(members: TeamMember[]): TeamMember[] {
  return members.map((member) => ({
    email: member.email.trim().toLowerCase(),
    sourceIds: [...new Set(member.sourceIds)].sort(),
  })).sort((a, b) => a.email.localeCompare(b.email))
}

function withAdministrators(team: Team, members: TeamMember[]): TeamMember[] {
  const emails = new Set(members.map((member) => member.email.toLowerCase()))
  return canonicalMembers([
    ...members,
    ...team.adminEmails.filter((email) => !emails.has(email.toLowerCase())).map((email) => ({ email, sourceIds: [] })),
  ])
}

function isRecordedChange(action: TeamAction | null): boolean {
  return action?.status === 'authorization_required' || action?.status === 'applying' || action?.status === 'recovery_required'
}

function actionMessage(action: TeamAction | null): string | null {
  if (!action) return null
  if (action.status === 'succeeded') return 'The last recorded team access change was applied and verified in Cloudflare. Unsaved selections have not been applied.'
  const failure = action.failureCode && ['team_management_credential_missing', 'team_management_credential_invalid', 'team_policy_drift'].includes(action.failureCode)
    ? `${new GatewayApiError(409, action.failureCode).message} `
    : ''
  if (action.status === 'recovery_required') return `${failure}Some access policies may already have changed. Resume the exact recorded change below. Nothing was automatically restored.`
  if (action.status === 'applying') return 'Applying and verifying team access. Some policies may already have changed; the saved configuration below is not a live check.'
  if (action.status === 'failed') return action.failureCode === 'team_action_cancelled'
    ? 'The recorded change was canceled before any access policy was changed.'
    : `${failure}The recorded team access change did not complete. Review the saved configuration before trying again.`
  return 'This proposal is retained in your gateway. Save the exact recorded change here to apply and verify it in your Cloudflare account. Hosted authorization is no longer used.'
}

export function TeamPage() {
  const preview = isGatewayUiPreview()
  const { getTeam, getTeamAction, prepareTeamAction, cancelTeamAction, isBusy, sources, externalChangeVersion } = useGateway()
  const [team, setTeam] = useState<Team | null>(null)
  const [draft, setDraft] = useState<TeamMember[]>([])
  const [action, setAction] = useState<TeamAction | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [email, setEmail] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const [needsRefresh, setNeedsRefresh] = useState(false)
  const actionInFlight = useRef(false)
  const seenExternalChange = useRef(externalChangeVersion)
  const teamReadGeneration = useRef(0)
  const [callbackId, setCallbackId] = useState(() => {
    const value = new URL(window.location.href).searchParams.get('accessAction')
    return value && ACTION_ID.test(value) ? value : null
  })

  const clearCallback = useCallback(() => {
    setCallbackId(null)
    const url = new URL(window.location.href)
    url.searchParams.delete('accessAction')
    url.searchParams.delete('accessActionResult')
    window.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`)
  }, [])

  const acceptTeam = useCallback((next: Team) => {
    setTeam(next)
    setAction(next.pendingAction)
    setDraft(withAdministrators(next, next.members))
    setNeedsRefresh(false)
    setFormError(null)
    if (next.pendingAction && !['authorization_required', 'applying'].includes(next.pendingAction.status)) clearCallback()
  }, [clearCallback])

  const readTeam = useCallback(async (showLoading = true) => {
    const generation = ++teamReadGeneration.current
    if (showLoading) setLoading(true)
    try {
      const next = await getTeam()
      if (generation !== teamReadGeneration.current) return false
      acceptTeam(next)
      return true
    } catch (cause) {
      if (generation !== teamReadGeneration.current) return false
      throw cause
    } finally {
      if (generation === teamReadGeneration.current) setLoading(false)
    }
  }, [acceptTeam, getTeam])

  const refresh = useCallback(async () => {
    setError(null)
    try {
      if (await readTeam()) clearCallback()
    }
    catch {
      setNeedsRefresh(true)
      setError('Team access could not be loaded. Refresh to check the saved configuration and any recorded change before continuing.')
    }
  }, [clearCallback, readTeam])

  useEffect(() => {
    let active = true
    void readTeam().catch(() => {
      if (active) setError('Team access could not be loaded. Refresh to try again.')
    })
    const url = new URL(window.location.href)
    if (url.searchParams.has('accessActionResult')) {
      url.searchParams.delete('accessActionResult')
      window.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`)
    }
    return () => { active = false; teamReadGeneration.current += 1 }
  }, [readTeam])

  const actionId = action?.actionId ?? callbackId
  const shouldPoll = team !== null && !loading && !saving && !isBusy && !needsRefresh && (action?.status === 'applying' || callbackId !== null)

  useEffect(() => {
    if (!actionId || !shouldPoll) return
    let active = true
    let timer: number | undefined
    const poll = async () => {
      try {
        const next = await getTeamAction(actionId)
        if (!active) return
        if (next.actionId !== actionId) throw new Error('action_mismatch')
        if (next.status === 'succeeded' || next.status === 'failed' || next.status === 'recovery_required') {
          if (await readTeam(false)) clearCallback()
          return
        }
        setAction(next)
        clearCallback()
        if (next.status === 'authorization_required') return
        timer = window.setTimeout(() => { void poll() }, 1500)
      } catch {
        if (active) {
          setNeedsRefresh(true)
          setError('The team access action status is unavailable. Refresh to check it before continuing. The saved configuration is not proof of live access.')
        }
      }
    }
    void poll()
    return () => { active = false; window.clearTimeout(timer) }
  }, [actionId, clearCallback, readTeam, getTeamAction, shouldPoll])

  const administrators = useMemo(() => new Set(team?.adminEmails.map((value) => value.toLowerCase()) ?? []), [team?.adminEmails])
  const effectiveMembers = useMemo(() => team ? withAdministrators(team, team.members) : [], [team])
  const recorded = isRecordedChange(action)
  const displayedMembers = recorded ? team?.proposedMembers ?? [] : draft
  const changed = JSON.stringify(canonicalMembers(draft)) !== JSON.stringify(effectiveMembers)
  useEffect(() => {
    if (seenExternalChange.current === externalChangeVersion) return
    seenExternalChange.current = externalChangeVersion
    if (changed || actionInFlight.current) {
      setNeedsRefresh(true)
      setError('Gateway state may have changed through another action. Your unsaved selections were preserved. Refresh to review the saved team before continuing.')
      return
    }
    void refresh()
  }, [externalChangeVersion, changed, refresh])
  const installed = team?.sources.filter((source) => source.status === 'installed') ?? []
  const message = actionMessage(action)
  const disabled = isBusy || saving || loading || needsRefresh || callbackId !== null || recorded || team?.editingEnabled !== true
  const atCapacity = draft.length >= TEAM_MAX_PEOPLE
  const canCancel = team?.editingEnabled === true && (action?.status === 'authorization_required' || action?.status === 'recovery_required') && action.canCancel === true

  const addPerson = (event: FormEvent) => {
    event.preventDefault()
    if (disabled) return
    const normalized = email.trim().toLowerCase()
    if (atCapacity) {
      setFormError(`Your team can have up to ${TEAM_MAX_PEOPLE} people, including administrators.`)
      return
    }
    if (normalized.length > 254 || !EMAIL.test(normalized)) {
      setFormError('Enter a valid email address, up to 254 characters.')
      return
    }
    if (draft.some((member) => member.email === normalized)) {
      setFormError('This person is already in your team.')
      return
    }
    setDraft((current) => canonicalMembers([...current, { email: normalized, sourceIds: [] }]))
    setEmail('')
    setFormError(null)
  }

  const save = async () => {
    if (!team?.editingEnabled || !team.managementCredentialConfigured || loading || isBusy || needsRefresh || callbackId !== null || actionInFlight.current || action?.status === 'applying' || (!recorded && !changed)) return
    const members = recorded ? team.proposedMembers : canonicalMembers(draft)
    if (!members) return
    actionInFlight.current = true
    setSaving(true)
    setError(null)
    try {
      const { action: pendingAction } = await prepareTeamAction(team.revision, members)
      if (!ACTION_ID.test(pendingAction.actionId) || (recorded && pendingAction.actionId !== action?.actionId)) {
        throw new GatewayApiError(502, 'team_action_invalid')
      }
      setAction(pendingAction)
      setTeam((current) => current ? { ...current, pendingAction, proposedMembers: members } : current)
      if (await readTeam()) clearCallback()
    } catch (cause) {
      setNeedsRefresh(true)
      setError(cause instanceof GatewayApiError ? cause.message : 'The team access change could not be confirmed. Refresh to check the recorded state before trying again.')
    } finally { actionInFlight.current = false; setSaving(false) }
  }

  const cancelRecordedChange = async () => {
    if (!canCancel || !action || loading || isBusy || needsRefresh || callbackId !== null || actionInFlight.current) return
    actionInFlight.current = true
    setError(null)
    try {
      const canceled = await cancelTeamAction(action.actionId)
      if (canceled.actionId !== action.actionId || canceled.status !== 'failed' || canceled.failureCode !== 'team_action_cancelled') {
        throw new GatewayApiError(409, 'team_cancel_failed')
      }
      if (await readTeam()) clearCallback()
    } catch (cause) {
      setNeedsRefresh(true)
      setError(cause instanceof GatewayApiError ? cause.message : 'Cancellation could not be confirmed. Refresh to check the recorded change before trying again.')
    } finally { actionInFlight.current = false }
  }

  return (
    <div>
      <PageHeader
        title="Team"
        description={team?.editingEnabled ? 'Choose which MCP sources each person can use. Save applies the whole change through your gateway in your Cloudflare account.' : 'Inspect the source access saved for your team and the tools each source shares.'}
        action={<Button variant="secondary" className="pressable inline-flex items-center gap-2" loading={loading} disabled={isBusy || saving || (!needsRefresh && !recorded && changed)} onClick={() => void refresh()}><ArrowsClockwise size={16} /> Refresh</Button>}
      />

      {preview ? <p role="status" className="notice-banner notice-neutral mt-6">Local preview — synthetic people; no Cloudflare changes. Saving is simulated and stays on this page.</p> : null}
      {error ? <p role="alert" className="notice-banner notice-error mt-6">{error}</p> : null}
      {message ? <p role="status" className={`notice-banner mt-6 notice-${action?.status === 'succeeded' ? 'success' : action?.status === 'failed' || action?.status === 'recovery_required' ? 'error' : 'neutral'}`}>{message}</p> : null}
      {!team ? <p className="mt-8 text-sm text-kumo-subtle">{loading ? 'Loading team access…' : 'No team access information is available.'}</p> : (
        <>
          {!team.editingEnabled ? <p role="status" className="notice-banner notice-neutral mt-6">{team.editingDisabledReason === 'lifecycle_action_pending' ? 'Another source, update, or teardown action is in progress. Finish or safely cancel that action, then refresh to edit team access.' : 'Team access changes are disabled until this gateway release is reviewed and approved.'} You can still inspect the saved access configuration and shared tools.</p> : null}
          {!team.managementCredentialConfigured ? <p role="status" className="notice-banner notice-neutral mt-6">Team saves need a dedicated Cloudflare management API token. Its Access permission can administer other applications and policies in the same account. Follow the <a href="https://github.com/ValentinOtt/ankka-mcp-gateway/blob/main/docs/TEAM_ACCESS.md" target="_blank" rel="noreferrer" className="underline underline-offset-4">Team credential setup guide</a> for required permissions, rotation, and revocation. In your Cloudflare account, open this gateway Worker’s Settings → Variables and Secrets and add it as the encrypted secret <code>ANKKA_TEAM_MANAGEMENT_TOKEN</code>, then refresh. Never paste the token into this dashboard or send it to Ankka. Adding the secret does not apply a recorded change; review it here before saving.</p> : null}
          {sources && sources.installationEnabled !== true ? <p role="status" className="notice-banner notice-neutral mt-6">{SOURCE_ADDITION_PAUSED_MESSAGE} {team.editingEnabled ? 'You can grant or revoke access to the installed sources below.' : 'This restriction does not change saved access.'}</p> : null}
          {needsRefresh ? <p role="status" className="notice-banner notice-neutral mt-6">Editing is paused until the recorded state can be checked. Refresh reloads the saved configuration and discards unsaved selections.</p> : null}
          <section className="surface-card mt-7 p-5 sm:p-6" aria-labelledby="team-admins-title">
            <div className="flex items-center gap-2"><ShieldCheck size={18} /><h2 id="team-admins-title" className="text-base font-semibold text-kumo-strong">Administrators</h2></div>
            <p className="mt-2 max-w-[75ch] text-sm leading-6 text-kumo-subtle">Administrators manage this gateway. Their roles are fixed in the deployment configuration and cannot be changed here. {team.editingEnabled ? 'Source access is separate and can be changed below, including for administrators.' : 'Source access is shown separately below; edits are disabled in this release.'}</p>
            <ul className="mt-4 flex flex-wrap gap-2" aria-label="Gateway administrators">
              {team.adminEmails.map((value) => <li key={value} className="tool-chip break-all">{value}</li>)}
            </ul>
          </section>

          <section className="surface-card mt-5 p-5 sm:p-6" aria-labelledby="verified-access-title">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 id="verified-access-title" className="text-base font-semibold text-kumo-strong">Saved access configuration</h2>
              <span className="text-xs text-kumo-subtle">Revision {team.revision}</span>
            </div>
            <p className="mt-2 text-sm leading-6 text-kumo-subtle">This is the configuration saved by your gateway, not your unsaved selections or a live Cloudflare policy check. Changes made directly in Cloudflare are not reflected here.</p>
            <ul className="mt-4 divide-y divide-kumo-line" aria-label="Saved team access">
              {effectiveMembers.map((member) => (
                <li key={member.email} className="flex flex-col gap-1 py-3 text-sm sm:flex-row sm:justify-between sm:gap-5">
                  <span className="break-all font-medium text-kumo-strong">{member.email}</span>
                  <span className="text-kumo-subtle sm:text-right">{member.sourceIds.length ? member.sourceIds.map((id) => team.sources.find((source) => source.id === id)?.label ?? 'Unavailable source').join(', ') : 'No source access'}</span>
                </li>
              ))}
              {effectiveMembers.length === 0 ? <li className="py-3 text-sm text-kumo-subtle">No people have been configured.</li> : null}
            </ul>
          </section>

          <section className="surface-card mt-5 p-5 sm:p-6" aria-labelledby="edit-access-title">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 id="edit-access-title" className="text-base font-semibold text-kumo-strong">{recorded ? 'Recorded change' : team.editingEnabled ? 'Edit source access' : 'Source access'}</h2>
                <p className="mt-1 text-sm leading-6 text-kumo-subtle">{recorded ? canCancel ? 'This proposal is retained by your gateway. Save this exact change, or cancel it before any policy is changed.' : 'This proposal is retained by your gateway. It must be completed exactly before another change can be made.' : team.editingEnabled ? 'New people start with no sources. Selecting an installed source grants its shared enabled tools, not administrator access.' : 'Each source grants its shared enabled tools. Source grants do not change administrator roles.'}</p>
              </div>
              <StatusPill tone={recorded || changed ? 'attention' : 'waiting'}>{recorded ? 'Not fully verified' : changed ? 'Unsaved changes' : 'No unsaved changes'}</StatusPill>
            </div>

            {recorded && team.proposedMembers === null ? <p role="alert" className="field-error">The recorded proposal is unavailable. Refresh to retrieve it; a different change cannot be submitted.</p> : null}

            <div className="mt-5 grid gap-4">
              {displayedMembers.map((member) => (
                <fieldset key={member.email} disabled={disabled} className="min-w-0 rounded-lg border border-kumo-line p-4">
                  <legend className="max-w-full break-all px-1 text-sm font-semibold text-kumo-strong">{member.email}</legend>
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <span className="text-xs text-kumo-subtle">{administrators.has(member.email) ? 'Administrator · role unchanged' : 'Team member'}</span>
                    {!administrators.has(member.email) && !recorded ? <Button type="button" variant="secondary" className="pressable inline-flex items-center gap-2" aria-label={`Remove ${member.email}`} onClick={() => setDraft((current) => current.filter((person) => person.email !== member.email))}><Trash size={14} /> Remove person</Button> : null}
                  </div>
                  <div className="mt-3 grid gap-2 sm:grid-cols-2">
                    {installed.map((source) => (
                      <label key={source.id} className="tool-option-card">
                        <input type="checkbox" checked={member.sourceIds.includes(source.id)} onChange={(event) => {
                          const checked = event.target.checked
                          setDraft((current) => current.map((person) => person.email === member.email ? { ...person, sourceIds: checked ? [...new Set([...person.sourceIds, source.id])] : person.sourceIds.filter((id) => id !== source.id) } : person))
                        }} />
                        <span className="text-sm">{source.label}<span className="mt-0.5 block text-xs text-kumo-subtle">{source.enabledTools.length} shared tool{source.enabledTools.length === 1 ? '' : 's'}</span></span>
                      </label>
                    ))}
                    {installed.length === 0 ? <p className="text-sm text-kumo-subtle">{sources?.installationEnabled === true ? 'Install a source before granting source access.' : 'No installed sources are available to assign. New-source installation is paused.'}</p> : null}
                  </div>
                  {member.sourceIds.length === 0 ? <p className="mt-3 text-xs text-kumo-subtle">No sources selected.</p> : null}
                </fieldset>
              ))}
            </div>

            {!recorded ? (
              <form onSubmit={addPerson} className="mt-5 flex flex-col gap-3 border-t border-kumo-line pt-5 sm:flex-row sm:items-end">
                <Input label="Person’s email" type="email" autoComplete="off" required maxLength={254} className="w-full sm:max-w-sm" placeholder="teammate@example.com" value={email} disabled={disabled || atCapacity} onChange={(event) => { setEmail(event.target.value); setFormError(null) }} />
                <Button type="submit" variant="secondary" className="pressable inline-flex items-center gap-2" disabled={disabled || atCapacity || !email.trim()}><Plus size={16} /> Add person</Button>
              </form>
            ) : null}
            {!recorded ? <p className="mt-2 text-xs text-kumo-subtle">{draft.length} of {TEAM_MAX_PEOPLE} people, including administrators.{atCapacity ? ' Remove a team member before adding another person.' : ''}</p> : null}
            {formError ? <p role="alert" className="field-error">{formError}</p> : null}

            <div className="mt-5 flex flex-wrap items-center gap-3 border-t border-kumo-line pt-5">
              <Button variant="primary" className="pressable inline-flex items-center gap-2" loading={isBusy || saving} disabled={!team.editingEnabled || !team.managementCredentialConfigured || loading || saving || isBusy || needsRefresh || callbackId !== null || action?.status === 'applying' || (recorded ? team.proposedMembers === null : !changed)} onClick={() => void save()}>
                <Check size={16} /> {action?.status === 'recovery_required' ? 'Resume recorded change' : recorded ? 'Save recorded change' : 'Save'}
              </Button>
              {canCancel ? <Button variant="secondary" className="pressable inline-flex items-center gap-2" disabled={isBusy || saving || loading || needsRefresh || callbackId !== null} onClick={() => void cancelRecordedChange()}><X size={16} /> Cancel recorded change</Button> : null}
              {!recorded && changed ? <Button variant="secondary" className="pressable inline-flex items-center gap-2" disabled={isBusy || saving} onClick={() => { setDraft(effectiveMembers); setFormError(null) }}>Discard unsaved changes</Button> : null}
              <p className="max-w-[65ch] text-xs leading-5 text-kumo-subtle">Access is not confirmed until Cloudflare applies and verifies the change. Existing cached sessions may remain valid until they expire or are revoked in Cloudflare Access.</p>
            </div>
            <p className="mt-3 max-w-[75ch] text-xs leading-5 text-kumo-subtle">After the first permission-policy change, automatic teardown is unavailable until a compatible gateway release supports it.</p>
          </section>

          <section className="surface-card mt-5 p-5 sm:p-6" aria-labelledby="shared-tools-title">
            <h2 id="shared-tools-title" className="text-base font-semibold text-kumo-strong">Shared source tools</h2>
            <p className="mt-2 max-w-[75ch] text-sm leading-6 text-kumo-subtle">Everyone granted a source gets the same enabled tools. This page does not set per-person tool permissions. Review the shared allowlist in <a href="/sources" className="underline underline-offset-4">Sources</a>.</p>
            <div className="mt-4 divide-y divide-kumo-line">
              {team.sources.map((source) => (
                <details key={source.id} className="py-3">
                  <summary className="cursor-pointer text-sm font-medium text-kumo-strong">{source.label} · {source.enabledTools.length} tools{source.status === 'draft' ? ' · Draft, not assignable' : ''}</summary>
                  <ul className="mt-3 flex max-h-56 flex-wrap gap-2 overflow-y-auto" aria-label={`${source.label} enabled tools`}>
                    {source.enabledTools.map((tool) => <li key={tool} className="tool-chip break-all"><code>{tool}</code></li>)}
                  </ul>
                </details>
              ))}
              {team.sources.length === 0 ? <p className="py-3 text-sm text-kumo-subtle">No MCP sources yet.</p> : null}
            </div>
          </section>
        </>
      )}
    </div>
  )
}
