import {
  createContext,
  type PropsWithChildren,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import * as v from 'valibot'
import {
  GatewayApiError,
  type GatewayAdminApi,
  type GatewayStatus,
  HttpGatewayAdminApi,
  SOURCE_ADDITION_PAUSED_MESSAGE,
  type ManagedSources,
  type PreparedAction,
  type RuntimeOperation,
  type RuntimeUpdate,
  type SourceActions,
  type SourceDiscovery,
  type SourceDraftInput,
  type Team,
  type TeamAction,
  type TeamActionResult,
  type TeamMember,
  validHandoffUrl,
} from './api'

type Notice = { tone: 'neutral' | 'success' | 'warning' | 'error'; message: string } | null

interface GatewayContextValue {
  api: GatewayAdminApi
  status: GatewayStatus | null
  sources: ManagedSources | null
  sourceActions: SourceActions | null
  sourceActionsError: string | null
  isCheckingSourceActions: boolean
  sourceActionsPollingPaused: boolean
  update: RuntimeUpdate | null
  isLoading: boolean
  isBusy: boolean
  hasLoaded: boolean
  error: string | null
  sourceNotice: Notice
  updateNotice: Notice
  externalChangeVersion: number
  reload(): Promise<void>
  refreshAfterExternalChange(): Promise<void>
  refreshSources(): Promise<ManagedSources>
  refreshSourceActions(): Promise<SourceActions>
  cancelSourceApply(actionId: string): Promise<void>
  refreshUpdate(): Promise<RuntimeUpdate>
  clearError(): void
  clearSourceNotice(): void
  clearUpdateNotice(): void
  discoverSource(url: string): Promise<SourceDiscovery>
  saveSourceDraft(source: SourceDraftInput): Promise<ManagedSources>
  prepareSourceApply(sourceId: string): Promise<PreparedAction>
  prepareRuntimeAction(operation: RuntimeOperation): Promise<PreparedAction>
  prepareTeardownAction(): Promise<PreparedAction>
  getTeam(): Promise<Team>
  prepareTeamAction(expectedRevision: number, members: TeamMember[]): Promise<TeamActionResult>
  getTeamAction(actionId: string): Promise<TeamAction>
  cancelTeamAction(actionId: string): Promise<TeamAction>
}

interface GatewayProviderProps extends PropsWithChildren {
  api?: GatewayAdminApi
}

const GatewayContext = createContext<GatewayContextValue | null>(null)
const ACTION_ID = /^action_[A-Za-z0-9_-]{32}$/u
const SOURCE_ACTION_POLL_INTERVAL = 5_000
const SOURCE_ACTION_POLL_LIMIT = 60
const SOURCE_ACTION_STATUS_UNAVAILABLE = 'Source action status is temporarily unavailable. Check status before authorizing another source.'

function errorMessage(cause: Error | null): string {
  return cause?.message ?? 'The gateway request failed.'
}

function unavailableUpdate(): RuntimeUpdate {
  return {
    schemaVersion: 1,
    channel: 'stable',
    status: 'unavailable',
    current: null,
    available: null,
    rollback: { available: false },
  }
}

function removeResultParameter(name: string) {
  const url = new URL(window.location.href)
  url.searchParams.delete(name)
  window.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`)
}

export function GatewayProvider({ children, api }: GatewayProviderProps) {
  const apiRef = useRef<GatewayAdminApi>(api ?? new HttpGatewayAdminApi())
  const [status, setStatus] = useState<GatewayStatus | null>(null)
  const [sources, setSources] = useState<ManagedSources | null>(null)
  const [sourceActions, setSourceActions] = useState<SourceActions | null>(null)
  const [sourceActionsError, setSourceActionsError] = useState<string | null>(null)
  const [isCheckingSourceActions, setIsCheckingSourceActions] = useState(false)
  const [sourceActionsPollingPaused, setSourceActionsPollingPaused] = useState(false)
  const [update, setUpdate] = useState<RuntimeUpdate | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [busyCount, setBusyCount] = useState(0)
  const [hasLoaded, setHasLoaded] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [sourceNotice, setSourceNotice] = useState<Notice>(null)
  const [updateNotice, setUpdateNotice] = useState<Notice>(null)
  const [externalChangeVersion, setExternalChangeVersion] = useState(0)
  const mounted = useRef(true)
  const sourceActionRead = useRef(0)
  const reconciledSourceActions = useRef(new Set<string>())

  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false; sourceActionRead.current += 1 }
  }, [])

  const runBusy = useCallback(async <T,>(operation: () => Promise<T>): Promise<T> => {
    setBusyCount((count) => count + 1)
    setError(null)
    try { return await operation() }
    catch (requestError) {
      const parsed = v.safeParse(v.instance(Error), requestError)
      setError(errorMessage(parsed.success ? parsed.output : null))
      throw requestError
    } finally { setBusyCount((count) => Math.max(0, count - 1)) }
  }, [])

  const refreshSources = useCallback(async () => {
    const next = await apiRef.current.getSources()
    setSources((current) => current && current.revision > next.revision ? current : next)
    return next
  }, [])

  const refreshSourceActions = useCallback(async (): Promise<SourceActions> => {
    const read = ++sourceActionRead.current
    setIsCheckingSourceActions(true)
    try {
      const next = await apiRef.current.getSourceActions()
      if (!mounted.current || read !== sourceActionRead.current) return next
      setSourceActions(next)
      const completed = next.actions.filter((action) => action.state === 'succeeded' && !reconciledSourceActions.current.has(action.actionId))
      if (completed.length > 0) {
        await refreshSources()
        for (const action of completed) reconciledSourceActions.current.add(action.actionId)
      }
      if (mounted.current && read === sourceActionRead.current) setSourceActionsError(null)
      return next
    } catch {
      if (mounted.current && read === sourceActionRead.current) setSourceActionsError(SOURCE_ACTION_STATUS_UNAVAILABLE)
      throw new Error(SOURCE_ACTION_STATUS_UNAVAILABLE)
    } finally {
      if (mounted.current && read === sourceActionRead.current) setIsCheckingSourceActions(false)
    }
  }, [refreshSources])

  const cancelSourceApply = useCallback((actionId: string) => runBusy(async () => {
    try {
      await apiRef.current.cancelSourceAction(actionId)
    } catch (cause) {
      throw cause instanceof GatewayApiError ? cause : new Error('Cancellation could not be confirmed. Check status before starting another authorization.')
    } finally {
      await refreshSourceActions().catch(() => {})
    }
  }), [refreshSourceActions, runBusy])

  const getTeam = useCallback(() => apiRef.current.getTeam(), [])
  const getTeamAction = useCallback((actionId: string) => apiRef.current.getTeamAction(actionId), [])

  const refreshUpdate = useCallback(async () => {
    try {
      const next = await apiRef.current.getUpdate()
      setUpdate(next)
      return next
    } catch {
      const next = unavailableUpdate()
      setUpdate(next)
      return next
    }
  }, [])

  const reload = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    const actionRefresh = refreshSourceActions().catch(() => {})
    try {
      const [nextStatus, nextSources] = await Promise.all([
        apiRef.current.getStatus(),
        apiRef.current.getSources(),
      ])
      setStatus(nextStatus)
      setSources((current) => current && current.revision > nextSources.revision ? current : nextSources)
      setHasLoaded(true)
      await refreshUpdate()
    } catch (requestError) {
      const parsed = v.safeParse(v.instance(Error), requestError)
      setError(errorMessage(parsed.success ? parsed.output : null))
    } finally {
      await actionRefresh
      setIsLoading(false)
    }
  }, [refreshSourceActions, refreshUpdate])

  const refreshAfterExternalChange = useCallback(async () => {
    setExternalChangeVersion((version) => version + 1)
    await reload()
  }, [reload])

  useEffect(() => { void reload() }, [reload])

  useEffect(() => {
    const check = () => { void refreshSourceActions().catch(() => {}) }
    const checkVisible = () => { if (document.visibilityState === 'visible') check() }
    window.addEventListener('focus', check)
    document.addEventListener('visibilitychange', checkVisible)
    return () => {
      window.removeEventListener('focus', check)
      document.removeEventListener('visibilitychange', checkVisible)
    }
  }, [refreshSourceActions])

  const sourceActionPollingKey = sourceActions?.blockingAction
    ? `${sourceActions.blockingAction.kind}:${sourceActions.blockingAction.actionId}`
    : null
  useEffect(() => {
    setSourceActionsPollingPaused(false)
    if (!sourceActionPollingKey) return
    let active = true
    let attempts = 0
    let timer: number | undefined
    const check = async () => {
      await refreshSourceActions().catch(() => {})
      if (!active) return
      attempts += 1
      if (attempts >= SOURCE_ACTION_POLL_LIMIT) {
        setSourceActionsPollingPaused(true)
        return
      }
      timer = window.setTimeout(() => { void check() }, SOURCE_ACTION_POLL_INTERVAL)
    }
    timer = window.setTimeout(() => { void check() }, SOURCE_ACTION_POLL_INTERVAL)
    return () => {
      active = false
      window.clearTimeout(timer)
    }
  }, [sourceActionPollingKey, refreshSourceActions])

  useEffect(() => {
    const url = new URL(window.location.href)
    const actionId = url.searchParams.get('sourceAction')
    const result = url.searchParams.get('sourceActionResult')
    const rawReason = url.searchParams.get('sourceActionReason')
    const reason = rawReason !== null && /^[a-z][a-z0-9_]{0,120}$/u.test(rawReason) ? rawReason : null
    const denied = result === 'denied'
    if (url.searchParams.has('sourceActionResult')) removeResultParameter('sourceActionResult')
    if (url.searchParams.has('sourceActionReason')) removeResultParameter('sourceActionReason')
    if (denied && actionId && ACTION_ID.test(actionId)) {
      // The authenticated endpoint checks again that provisioning has not started.
      void cancelSourceApply(actionId).catch(() => {})
    }
    if (result === 'failed') {
      setSourceNotice({ tone: 'neutral', message: `Cloudflare approved the request, but your gateway could not complete the installation${reason === null ? '' : ` (${reason})`}. Check the action status below before authorizing again.` })
    } else if (result === 'revocation_unconfirmed') {
      setSourceNotice({ tone: 'neutral', message: 'The source was installed, but the temporary Cloudflare permission could not be confirmed revoked. Review active OAuth grants in your Cloudflare profile.' })
    }
  }, [cancelSourceApply])

  useEffect(() => {
    const actionId = new URL(window.location.href).searchParams.get('sourceAction')
    if (actionId && ACTION_ID.test(actionId) && sources?.installationEnabled === false) {
      setSourceNotice({ tone: 'neutral', message: SOURCE_ADDITION_PAUSED_MESSAGE })
    }
  }, [sources?.installationEnabled])

  useEffect(() => {
    let active = true
    const url = new URL(window.location.href)
    const runtimeActionId = url.searchParams.get('runtimeAction')

    const delay = () => new Promise<void>((resolve) => window.setTimeout(resolve, 1500))
    const pollRuntime = async (actionId: string) => {
      if (url.searchParams.has('runtimeActionResult')) removeResultParameter('runtimeActionResult')
      while (active) {
        try {
          const action = await apiRef.current.getRuntimeAction(actionId)
          if (!active) return
          if (action.status === 'succeeded') {
            setUpdateNotice({
              tone: 'success',
              message: action.operation === 'rollback'
                ? 'Rollback verified. Durable Object data was preserved.'
                : 'Update activated and health-checked. Durable Object data was preserved.',
            })
            await reload()
            return
          }
          if (Date.parse(action.expiresAt) <= Date.now()) {
            setUpdateNotice({ tone: 'error', message: 'The one-time authorization expired. Start a fresh runtime action.' })
            return
          }
          if (action.status === 'failed' || action.status === 'recovery_required') {
            setUpdateNotice({ tone: 'error', message: 'The runtime action did not converge. Start a fresh authorization.' })
            return
          }
          setUpdateNotice({
            tone: 'neutral',
            message: action.status === 'applying'
              ? `Runtime action in progress: ${(action.stage ?? 'authorized').replaceAll('_', ' ')}…`
              : 'Waiting for Cloudflare authorization…',
          })
        } catch {
          setUpdateNotice({ tone: 'error', message: 'The runtime action status is temporarily unavailable.' })
          return
        }
        await delay()
      }
    }

    if (runtimeActionId && ACTION_ID.test(runtimeActionId)) void pollRuntime(runtimeActionId)
    return () => { active = false }
  }, [reload])

  const value = useMemo<GatewayContextValue>(() => ({
    api: apiRef.current,
    status,
    sources,
    sourceActions,
    sourceActionsError,
    isCheckingSourceActions,
    sourceActionsPollingPaused,
    update,
    isLoading,
    isBusy: busyCount > 0,
    hasLoaded,
    error,
    sourceNotice,
    updateNotice,
    externalChangeVersion,
    reload,
    refreshAfterExternalChange,
    refreshSources,
    refreshSourceActions,
    cancelSourceApply,
    refreshUpdate,
    clearError: () => setError(null),
    clearSourceNotice: () => setSourceNotice(null),
    clearUpdateNotice: () => setUpdateNotice(null),
    discoverSource: (url) => runBusy(() => apiRef.current.discoverSource(url)),
    saveSourceDraft: (source) => runBusy(async () => {
      const current = sources ?? await refreshSources()
      if (current.installationEnabled !== true) throw new GatewayApiError(409, 'source_addition_paused')
      const next = await apiRef.current.saveSourceDraft(current.revision, source)
      setSources((current) => current && current.revision > next.revision ? current : next)
      setSourceNotice({ tone: 'success', message: 'Draft saved inside your gateway. The live Portal was not changed.' })
      return next
    }),
    prepareSourceApply: (sourceId) => runBusy(async () => {
      const current = sources ?? await refreshSources()
      if (current.installationEnabled !== true) throw new GatewayApiError(409, 'source_addition_paused')
      const actions = await refreshSourceActions()
      if (actions.blockingAction) {
        const action = actions.blockingAction
        const summary = actions.actions.find((candidate) => candidate.actionId === action.actionId)
        throw new GatewayApiError(409, 'source_action_conflict', {
          reason: summary?.state === 'recovery_required' ? 'recovery_required' : action.kind === 'source' ? 'source_pending' : 'lifecycle_pending',
          action,
        })
      }
      try {
        const trustedStatus = status ?? await apiRef.current.getStatus()
        if (status === null) setStatus(trustedStatus)
        const prepared = await apiRef.current.prepareSourceAction(current.revision, sourceId)
        const handoffUrl = validHandoffUrl(prepared.handoffUrl, window.location.origin)
        if (!handoffUrl) throw new Error('The authorization link could not be verified.')
        return { ...prepared, handoffUrl }
      } catch (cause) {
        await refreshSources().catch(() => {})
        throw cause instanceof GatewayApiError ? cause : new Error('Source authorization could not be confirmed. Check status before trying again.')
      } finally {
        await refreshSourceActions().catch(() => {})
      }
    }),
    prepareRuntimeAction: (operation) => runBusy(async () => {
      const trustedStatus = status ?? await apiRef.current.getStatus()
      if (status === null) setStatus(trustedStatus)
      const prepared = await apiRef.current.prepareRuntimeAction(operation)
      const handoffUrl = validHandoffUrl(prepared.handoffUrl, window.location.origin)
      if (!handoffUrl) throw new Error('The authorization link could not be verified.')
      return { ...prepared, handoffUrl }
    }),
    prepareTeardownAction: () => runBusy(async () => {
      const trustedStatus = status ?? await apiRef.current.getStatus()
      if (status === null) setStatus(trustedStatus)
      const prepared = await apiRef.current.prepareTeardownAction()
      const handoffUrl = validHandoffUrl(prepared.handoffUrl, window.location.origin)
      if (!handoffUrl) throw new Error('The teardown handoff could not be verified.')
      return { ...prepared, handoffUrl }
    }),
    getTeam,
    getTeamAction,
    prepareTeamAction: (expectedRevision, members) => runBusy(async () => {
      try {
        return await apiRef.current.prepareTeamAction(expectedRevision, members)
      } catch (cause) {
        throw cause instanceof GatewayApiError ? cause : new GatewayApiError(502, 'team_prepare_failed')
      }
    }),
    cancelTeamAction: (actionId) => runBusy(async () => {
      try { return await apiRef.current.cancelTeamAction(actionId) }
      catch (cause) {
        throw cause instanceof GatewayApiError ? cause : new GatewayApiError(502, 'team_cancel_failed')
      }
    }),
  }), [
    busyCount, error, hasLoaded, isLoading, refreshSources, refreshUpdate, reload, runBusy,
    sourceNotice, sources, status, update, updateNotice, getTeam, getTeamAction,
    externalChangeVersion, refreshAfterExternalChange,
    sourceActions, sourceActionsError, isCheckingSourceActions, sourceActionsPollingPaused,
    refreshSourceActions, cancelSourceApply,
  ])

  return <GatewayContext.Provider value={value}>{children}</GatewayContext.Provider>
}

export function useGateway(): GatewayContextValue {
  const context = useContext(GatewayContext)
  if (!context) throw new Error('useGateway must be used inside GatewayProvider')
  return context
}
