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
  type SourceDiscovery,
  type SourceDraftInput,
  type Team,
  type TeamAction,
  type TeamActionResult,
  type TeamMember,
  validHandoffUrl,
} from './api'

type Notice = { tone: 'neutral' | 'success' | 'error'; message: string } | null

interface GatewayContextValue {
  status: GatewayStatus | null
  sources: ManagedSources | null
  update: RuntimeUpdate | null
  isLoading: boolean
  isBusy: boolean
  hasLoaded: boolean
  error: string | null
  sourceNotice: Notice
  updateNotice: Notice
  reload(): Promise<void>
  refreshSources(): Promise<ManagedSources>
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
  const [update, setUpdate] = useState<RuntimeUpdate | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [busyCount, setBusyCount] = useState(0)
  const [hasLoaded, setHasLoaded] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [sourceNotice, setSourceNotice] = useState<Notice>(null)
  const [updateNotice, setUpdateNotice] = useState<Notice>(null)

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
    setSources(next)
    return next
  }, [])

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
    try {
      const [nextStatus, nextSources] = await Promise.all([
        apiRef.current.getStatus(),
        apiRef.current.getSources(),
      ])
      setStatus(nextStatus)
      setSources(nextSources)
      setHasLoaded(true)
      await refreshUpdate()
    } catch (requestError) {
      const parsed = v.safeParse(v.instance(Error), requestError)
      setError(errorMessage(parsed.success ? parsed.output : null))
    } finally { setIsLoading(false) }
  }, [refreshUpdate])

  useEffect(() => { void reload() }, [reload])

  useEffect(() => {
    let active = true
    const url = new URL(window.location.href)
    const sourceActionId = url.searchParams.get('sourceAction')
    const runtimeActionId = url.searchParams.get('runtimeAction')

    const delay = () => new Promise<void>((resolve) => window.setTimeout(resolve, 1500))
    const pollSource = async (actionId: string) => {
      const denied = url.searchParams.get('sourceActionResult') === 'denied'
      if (url.searchParams.has('sourceActionResult')) removeResultParameter('sourceActionResult')
      while (active) {
        try {
          const action = denied
            ? await apiRef.current.cancelSourceAction(actionId)
            : await apiRef.current.getSourceAction(actionId)
          if (!active) return
          if (action.status === 'succeeded') {
            setSourceNotice({ tone: 'success', message: 'Source installed and the Cloudflare MCP Portal was updated.' })
            await reload()
            return
          }
          const currentSources = await apiRef.current.getSources()
          if (!active) return
          setSources(currentSources)
          if (currentSources.installationEnabled !== true) {
            setSourceNotice({ tone: 'neutral', message: SOURCE_ADDITION_PAUSED_MESSAGE })
            return
          }
          if (Date.parse(action.expiresAt) <= Date.now()) {
            setSourceNotice({ tone: 'error', message: 'The one-time authorization expired. Start a fresh authorization from the saved draft.' })
            return
          }
          if (action.status === 'failed' || action.status === 'recovery_required') {
            setSourceNotice({ tone: 'error', message: 'The source action needs a fresh authorization.' })
            return
          }
          setSourceNotice({
            tone: 'neutral',
            message: action.status === 'applying'
              ? 'Applying the source and verifying each Cloudflare resource…'
              : 'Waiting for Cloudflare authorization…',
          })
        } catch {
          setSourceNotice({ tone: 'error', message: 'The source action status is temporarily unavailable.' })
          return
        }
        await delay()
      }
    }

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

    if (sourceActionId && ACTION_ID.test(sourceActionId)) void pollSource(sourceActionId)
    if (runtimeActionId && ACTION_ID.test(runtimeActionId)) void pollRuntime(runtimeActionId)
    return () => { active = false }
  }, [reload])

  const value = useMemo<GatewayContextValue>(() => ({
    status,
    sources,
    update,
    isLoading,
    isBusy: busyCount > 0,
    hasLoaded,
    error,
    sourceNotice,
    updateNotice,
    reload,
    refreshSources,
    refreshUpdate,
    clearError: () => setError(null),
    clearSourceNotice: () => setSourceNotice(null),
    clearUpdateNotice: () => setUpdateNotice(null),
    discoverSource: (url) => runBusy(() => apiRef.current.discoverSource(url)),
    saveSourceDraft: (source) => runBusy(async () => {
      const current = sources ?? await refreshSources()
      if (current.installationEnabled !== true) throw new GatewayApiError(409, 'source_addition_paused')
      const next = await apiRef.current.saveSourceDraft(current.revision, source)
      setSources(next)
      setSourceNotice({ tone: 'success', message: 'Draft saved inside your gateway. The live Portal was not changed.' })
      return next
    }),
    prepareSourceApply: (sourceId) => runBusy(async () => {
      const current = sources ?? await refreshSources()
      if (current.installationEnabled !== true) throw new GatewayApiError(409, 'source_addition_paused')
      const trustedStatus = status ?? await apiRef.current.getStatus()
      if (status === null) setStatus(trustedStatus)
      const prepared = await apiRef.current.prepareSourceAction(current.revision, sourceId)
      const handoffUrl = validHandoffUrl(prepared.handoffUrl, trustedStatus.controlPlaneOrigin)
      if (!handoffUrl) throw new Error('The authorization link could not be verified.')
      return { ...prepared, handoffUrl }
    }),
    prepareRuntimeAction: (operation) => runBusy(async () => {
      const trustedStatus = status ?? await apiRef.current.getStatus()
      if (status === null) setStatus(trustedStatus)
      const prepared = await apiRef.current.prepareRuntimeAction(operation)
      const handoffUrl = validHandoffUrl(prepared.handoffUrl, trustedStatus.controlPlaneOrigin)
      if (!handoffUrl) throw new Error('The authorization link could not be verified.')
      return { ...prepared, handoffUrl }
    }),
    prepareTeardownAction: () => runBusy(async () => {
      const trustedStatus = status ?? await apiRef.current.getStatus()
      if (status === null) setStatus(trustedStatus)
      const prepared = await apiRef.current.prepareTeardownAction()
      const handoffUrl = validHandoffUrl(prepared.handoffUrl, trustedStatus.controlPlaneOrigin)
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
  ])

  return <GatewayContext.Provider value={value}>{children}</GatewayContext.Provider>
}

export function useGateway(): GatewayContextValue {
  const context = useContext(GatewayContext)
  if (!context) throw new Error('useGateway must be used inside GatewayProvider')
  return context
}
