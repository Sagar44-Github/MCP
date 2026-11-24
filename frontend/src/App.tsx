import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import LandingPage from './LandingPage'
import SentinelMark from './SentinelMark'
import {
  Activity,
  ArrowRight,
  Boxes,
  Check,
  CheckCircle2,
  ChevronDown,
  CircleAlert,
  Clock3,
  Code2,
  Database,
  ExternalLink,
  Fingerprint,
  GitBranch,
  Layers3,
  LoaderCircle,
  LockKeyhole,
  Network,
  Play,
  Radio,
  RefreshCw,
  Search,
  ShieldCheck,
  Sun,
  Moon,
  TerminalSquare,
  Workflow,
  Volume2,
  Square,
  XCircle,
  Zap,
} from 'lucide-react'

type ServerStatus = {
  name: string
  display_name: string
  transport: 'stdio'
  status: 'online' | 'offline'
  tools_count: number
  error?: string | null
}

type SinkReceipt = {
  object_id: string
  label: string
  destination: string
  trace_id: string
  bytes_received: number
  payload_sha256: string
  execution_count: number
  received_at: string
}

type Overview = {
  status: 'online' | 'degraded'
  servers_online: number
  servers_total: number
  tools_count: number
  policy_id: string | null
  policy_version: string | null
  policy_error: string | null
  servers: ServerStatus[]
  sink: {
    server: string
    execution_count: number
    last_receipt: SinkReceipt | null
  } | null
  sink_error: string | null
  metrics: { calls: number; blocked: number; warnings: number; errors: number }
}

type VoiceStatus = { available: boolean; provider: string; voice_id: string; model_id: string; text_fallback: boolean }
type VoiceBriefing = { query: string; event_id: string; trace_id: string; verdict: 'BLOCK'; policy_id: string; text: string; audio_available: boolean }

type ToolDefinition = {
  name: string
  title: string | null
  description: string
  input_schema: Record<string, unknown>
  server: string
}

type SecurityEvent = {
  event_id: string
  timestamp: string
  request_id: string
  trace_id: string
  session_id: string
  server: string
  tool: string
  argument_keys: string[]
  outcome: 'completed' | 'blocked' | 'failed' | 'unknown'
  decision: { verdict: 'ALLOW' | 'WARN' | 'ASK' | 'BLOCK'; policy_id: string; policy_version: string; reasons: string[]; normalized_destination?: string | null }
  downstream_executed: boolean | null
  duration_ms: number
  object_id: string | null
  object_label: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED' | 'UNKNOWN'
  parent_object_ids: string[]
  destination: string | null
  detail: string
}

type JourneyResult = {
  request_id: string
  trace_id: string
  session_id: string
  verdict: 'ALLOW' | 'WARN' | 'ASK' | 'BLOCK'
  decision: SecurityEvent['decision']
  steps: Array<{ tool: string; server: string; event: SecurityEvent; result: Record<string, unknown> | null }>
  source: Record<string, unknown>
  sources: Array<Record<string, unknown>>
  derived: Record<string, unknown>
  receipt: SinkReceipt | null
  lineage: LineageGraph
  sink_execution_before: number
  sink_execution_after: number
  message: string
  phase_note: string
  pending_approval: ApprovalAction | null
}

type PolicySet = { status: string; policy_id?: string; version?: string; agents?: Record<string, { allow: string[]; deny: string[] }>; trusted_destinations?: string[]; unknown_lineage_external_verdict?: string; rules?: Array<{ id: string; title: string; effect: string; priority: number }>; error?: string }
type LineageNode = {
  kind: 'data_object' | 'destination'
  object_id?: string
  label?: 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED' | 'UNKNOWN'
  source?: string
  source_tool?: string
  parent_ids?: string[]
  transformation?: string | null
  lineage_confidence?: number
  destination_id?: string
  destination?: string
  verdict?: string
  downstream_executed?: boolean | null
  reason?: string
}
type LineageGraph = {
  trace_id: string
  nodes: LineageNode[]
  edges: Array<{ source_id: string | null; target_id: string; relation: string; transformation: string }>
}
type Scenario = 'public_to_approved_sink' | 'confidential_to_external_sink' | 'multi_parent_inheritance' | 'restricted_to_approved_sink'
type Page = 'overview' | 'tools' | 'lineage' | 'policies' | 'risk' | 'approvals'
type Theme = 'dark' | 'light'
type DriftChange = { path: string; kind: 'added' | 'removed' | 'changed'; before: string | null; after: string | null }
type DriftItem = { name: string; server: string; status: 'unchanged' | 'changed' | 'added' | 'removed' | 'unbaselined'; approved_fingerprint: string | null; current_fingerprint: string | null; changes: DriftChange[] }
type ApprovalAction = {
  action_id: string
  request_hash: string
  tool_name: string
  argument_names: string[]
  object_id: string | null
  data_label: SecurityEvent['object_label']
  destination: string
  payload_sha256: string
  policy_id: string
  policy_version: string
  reason: string
  agent_id: string
  request_id: string
  trace_id: string
  session_id: string
  event_id: string | null
  created_at: string
  expires_at: string
  status: 'pending' | 'approved' | 'denied' | 'executing' | 'executed' | 'expired' | 'failed'
  approver_id: string | null
  decision_at: string | null
  rationale: string | null
  executed_by: string | null
  executed_at: string | null
  downstream_executed: boolean
  receipt: (SinkReceipt & { server?: string }) | null
  last_error: string | null
  sanitized_arguments: { object_id: string | null; label: SecurityEvent['object_label']; destination: string; trace_id: string; payload: string }
}
type SecurityPosture = {
  drift: {
    baseline_status: 'active' | 'missing' | 'error'
    baseline_error: string | null
    approved_at: string | null
    discovery_status: 'ready' | 'waiting'
    demo_simulation: boolean
    drift_detected: boolean
    summary: { unchanged: number; changed: number; added: number; removed: number; unbaselined: number }
    items: DriftItem[]
  }
  risk: {
    score: number
    level: 'LOW' | 'GUARDED' | 'ELEVATED' | 'CRITICAL'
    scope: string
    factors: Array<{ id: string; title: string; points: number; active: boolean; explanation: string }>
    policy_override: boolean
    policy_note: string
  }
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(path, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...init?.headers },
    })
  } catch {
    throw new Error('Sentinel API is unreachable. Start the backend in the first terminal.')
  }

  if (!response.ok) {
    let detail = `API request failed (${response.status}).`
    try {
      const payload = await response.json()
      const value = payload?.detail
      detail = typeof value === 'string' ? value : value?.message || detail
    } catch {
      // Keep the status message when the response has no JSON body.
    }
    throw new Error(detail)
  }
  return (await response.json()) as T
}

async function apiAudio(path: string, init?: RequestInit): Promise<Blob> {
  let response: Response
  try {
    response = await fetch(path, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...init?.headers },
    })
  } catch {
    throw new Error('Sentinel API is unreachable. Start the backend in the first terminal.')
  }
  if (!response.ok) {
    let detail = `Audio request failed (${response.status}).`
    try {
      const payload = await response.json()
      detail = typeof payload?.detail === 'string' ? payload.detail : detail
    } catch {
      // Keep the HTTP status if the provider response is not JSON.
    }
    throw new Error(detail)
  }
  return response.blob()
}

function timeLabel(value: string) {
  return new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(
    new Date(value),
  )
}

function classNames(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(' ')
}

function App() {
  const [page, setPage] = useState<Page>('overview')
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const savedTheme = window.localStorage.getItem('mcp-sentinel-theme') === 'light' ? 'light' : 'dark'
      document.documentElement.dataset.theme = savedTheme
      return savedTheme
    } catch {
      document.documentElement.dataset.theme = 'dark'
      return 'dark'
    }
  })
  const [showLanding, setShowLanding] = useState(true)
  const [registryNavExpanded, setRegistryNavExpanded] = useState(false)
  const [serversExpanded, setServersExpanded] = useState(true)
  const [expandedServer, setExpandedServer] = useState<string | null>(null)
  const [selectedTool, setSelectedTool] = useState<ToolDefinition | null>(null)
  const [overview, setOverview] = useState<Overview | null>(null)
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [tools, setTools] = useState<ToolDefinition[]>([])
  const [policies, setPolicies] = useState<PolicySet | null>(null)
  const [posture, setPosture] = useState<SecurityPosture | null>(null)
  const [voiceStatus, setVoiceStatus] = useState<VoiceStatus | null>(null)
  const [approvals, setApprovals] = useState<ApprovalAction[]>([])
  const [approverToken, setApproverToken] = useState('')
  const [journey, setJourney] = useState<JourneyResult | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null)
  const [apiError, setApiError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [resetting, setResetting] = useState(false)
  const [resetCounter, setResetCounter] = useState(0)
  const [postureAction, setPostureAction] = useState(false)
  const [postureError, setPostureError] = useState<string | null>(null)
  const [approvalBusy, setApprovalBusy] = useState(false)
  const [approvalError, setApprovalError] = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const refresh = useCallback(async () => {
    try {
      const [nextOverview, nextEvents, nextTools, nextPolicies, nextPosture, nextApprovals, nextVoiceStatus] = await Promise.all([
        api<Overview>('/api/overview'),
        api<SecurityEvent[]>('/api/events?limit=100'),
        api<ToolDefinition[]>('/api/tools'),
        api<PolicySet>('/api/policies'),
        api<SecurityPosture>('/api/security-posture'),
        api<ApprovalAction[]>('/api/approvals?limit=50'),
        api<VoiceStatus>('/api/voice/status'),
      ])
      setOverview(nextOverview)
      setEvents(nextEvents)
      setTools(nextTools)
      setPolicies(nextPolicies)
      setPosture(nextPosture)
      setApprovals(nextApprovals)
      setVoiceStatus(nextVoiceStatus)
      setApiError(null)
      setLastUpdated(new Date())
    } catch (error) {
      setOverview(null)
      setEvents([])
      setTools([])
      setPolicies(null)
      setPosture(null)
      setApprovals([])
      setVoiceStatus(null)
      setJourney(null)
      setLastUpdated(null)
      setApiError(error instanceof Error ? error.message : 'Could not reach the Sentinel API.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
    const interval = window.setInterval(() => void refresh(), 2500)
    return () => window.clearInterval(interval)
  }, [refresh])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      window.localStorage.setItem('mcp-sentinel-theme', theme)
    } catch {
      // The theme remains active for this session when storage is unavailable.
    }
  }, [theme])

  const runJourney = async (scenario: Scenario) => {
    setRunning(true)
    setJourney(null)
    setSelectedEvent(null)
    setApiError(null)
    try {
      const result = await api<JourneyResult>('/api/scenarios/public-journey', {
        method: 'POST',
        body: JSON.stringify({ scenario }),
      })
      setJourney(result)
      await refresh()
    } catch (error) {
      setApiError(error instanceof Error ? error.message : 'The demo journey did not complete.')
      await refresh()
    } finally {
      setRunning(false)
    }
  }

  const resetDemo = async () => {
    setResetting(true)
    setApiError(null)
    try {
      await api<{ events_cleared: boolean; lineage_cleared: boolean; approvals_cleared: boolean; voice_cache_cleared: boolean }>('/api/demo/reset', { method: 'POST' })
      setJourney(null)
      setSelectedEvent(null)
      setResetCounter((counter) => counter + 1)
      await refresh()
    } catch (error) {
      setApiError(error instanceof Error ? error.message : 'The demo reset did not complete.')
    } finally {
      setResetting(false)
    }
  }

  const approveToolBaseline = async () => {
    setPostureAction(true)
    setPostureError(null)
    try {
      await api<SecurityPosture['drift']>('/api/tool-drift/approve', { method: 'POST' })
      await refresh()
    } catch (error) {
      setPostureError(error instanceof Error ? error.message : 'Could not capture the approved tool baseline.')
    } finally {
      setPostureAction(false)
    }
  }

  const toggleDriftDemo = async (enabled: boolean) => {
    setPostureAction(true)
    setPostureError(null)
    try {
      await api<SecurityPosture['drift']>('/api/tool-drift/demo', { method: 'POST', body: JSON.stringify({ enabled }) })
      await refresh()
    } catch (error) {
      setPostureError(error instanceof Error ? error.message : 'Could not update the drift demonstration.')
    } finally {
      setPostureAction(false)
    }
  }

  const actOnApproval = async (
    actionId: string,
    verb: 'approve' | 'deny' | 'execute',
    rationale?: string,
  ) => {
    setApprovalBusy(true)
    setApprovalError(null)
    try {
      await api<ApprovalAction>(`/api/approvals/${encodeURIComponent(actionId)}/${verb}`, {
        method: 'POST',
        headers: { 'X-Demo-Approver-Token': approverToken },
        ...(rationale === undefined ? {} : { body: JSON.stringify({ rationale }) }),
      })
      await refresh()
    } catch (error) {
      setApprovalError(error instanceof Error ? error.message : 'The approval action did not complete.')
    } finally {
      setApprovalBusy(false)
    }
  }

  const approveAction = (actionId: string, rationale: string) => actOnApproval(actionId, 'approve', rationale)
  const denyAction = (actionId: string, rationale: string) => actOnApproval(actionId, 'deny', rationale)
  const executeAction = (actionId: string) => actOnApproval(actionId, 'execute')

  const serverByName = useMemo(
    () => new Map((overview?.servers ?? []).map((server) => [server.name, server])),
    [overview],
  )

  const online = overview?.status === 'online'
  const visibleError = apiError ?? (overview?.policy_error ? `Policy engine unavailable: ${overview.policy_error}` : overview?.sink_error ? `Sink status unavailable: ${overview.sink_error}` : null)

  if (showLanding) {
    return (
      <LandingPage
        apiStatus={overview?.status ?? 'offline'}
        theme={theme}
        onToggleTheme={() => setTheme((current) => current === 'dark' ? 'light' : 'dark')}
        onOpenConsole={() => {
          setPage('overview')
          setShowLanding(false)
        }}
      />
    )
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#top" onClick={(event) => { event.preventDefault(); setShowLanding(true) }} aria-label="MCP Sentinel home">
          <span className="brand-mark"><SentinelMark /></span>
          <span className="brand-copy"><strong>Sentinel</strong></span>
        </a>

        <div className="workspace-select">
          <span className="workspace-avatar">M</span>
          <span className="workspace-text"><strong>Hackathon lab</strong><small>Local workspace</small></span>
        </div>

        <div className="nav-label">WORKSPACE</div>
        <nav className="side-nav" aria-label="Primary navigation">
          <button className={classNames('nav-item', page === 'overview' && 'active')} onClick={() => setPage('overview')}>
            <Activity size={16} /><span>Overview</span>
          </button>
          <div className="nav-group">
            <button className={classNames('nav-item', page === 'tools' && 'active')} onClick={() => { setSelectedTool(null); setPage('tools') }}>
              <Boxes size={16} /><span>Tool registry</span><span className="nav-count">{overview ? tools.length : '—'}</span>
            </button>
            <button className="nav-expand-button" onClick={() => setRegistryNavExpanded((expanded) => !expanded)} aria-label={`${registryNavExpanded ? 'Hide' : 'Show'} discovered tools`} aria-expanded={registryNavExpanded}>
              <ChevronDown className={classNames('nav-expand-icon', registryNavExpanded && 'expanded')} size={14} />
            </button>
          </div>
          {registryNavExpanded && <div className="nav-submenu">
            {tools.length ? tools.map((tool) => <button className="nav-subitem" key={tool.name} onClick={() => { setSelectedTool(tool); setPage('tools') }} title={tool.description}><Code2 size={13} /><span>{tool.name}</span></button>) : <span className="nav-subempty">Waiting for discovered tools</span>}
          </div>}
          <button className={classNames('nav-item', page === 'lineage' && 'active')} onClick={() => setPage('lineage')}>
            <GitBranch size={16} /><span>Lineage</span><span className="nav-count">{journey ? journey.lineage.nodes.length : '—'}</span>
          </button>
          <button className={classNames('nav-item', page === 'policies' && 'active')} onClick={() => setPage('policies')}>
            <LockKeyhole size={16} /><span>Policies</span><span className="nav-count">{policies?.version ?? '—'}</span>
          </button>
          <button className={classNames('nav-item', page === 'risk' && 'active')} onClick={() => setPage('risk')}>
            <ShieldCheck size={16} /><span>Risk &amp; drift</span><span className={classNames('nav-count', posture?.drift.drift_detected && 'risk-nav-alert')}>{posture?.drift.drift_detected ? '!' : posture?.risk.score ?? '—'}</span>
          </button>
          <button className={classNames('nav-item', page === 'approvals' && 'active')} onClick={() => setPage('approvals')}>
            <Clock3 size={16} /><span>Approvals</span><span className="nav-count">{approvals.filter((action) => action.status === 'pending').length}</span>
          </button>
        </nav>

        <button className="nav-label servers-heading server-group-toggle" onClick={() => setServersExpanded((expanded) => !expanded)} aria-expanded={serversExpanded}>
          <span>CONTROLLED SERVERS</span><span>{overview ? `${overview.servers_online}/3` : '—'}</span><ChevronDown className={classNames('nav-expand-icon', serversExpanded && 'expanded')} size={13} />
        </button>
        {serversExpanded && <div className="server-list">
          {(['reader', 'processor', 'sink'] as const).map((name) => {
            const server = serverByName.get(name)
            const serverTools = tools.filter((tool) => tool.server === name)
            const isExpanded = expandedServer === name
            return (
              <div className="server-nav-item" key={name}>
                <button className="server-nav-row" onClick={() => setExpandedServer(isExpanded ? null : name)} aria-expanded={isExpanded} title={server?.error ?? undefined}>
                  <span className={classNames('server-dot', server?.status === 'online' && 'online', !server && 'pending')} />
                  <span>{name}</span><span className="server-transport">{server?.tools_count ?? serverTools.length}</span><ChevronDown className={classNames('server-chevron', isExpanded && 'expanded')} size={13} />
                </button>
                {isExpanded && <div className="server-nav-details">
                  <span className={classNames('server-detail-status', server?.status === 'online' && 'online')}>{server?.status === 'online' ? 'Connected' : server?.status === 'offline' ? 'Offline' : 'Waiting for gateway'}</span>
                  {server?.error && <span className="server-detail-error">{server.error}</span>}
                  {serverTools.length ? serverTools.map((tool) => <button className="server-tool-link" key={tool.name} onClick={() => { setSelectedTool(tool); setPage('tools') }}><Code2 size={12} /><span>{tool.name}</span></button>) : <span className="nav-subempty">No tools discovered</span>}
                </div>}
              </div>
            )
          })}
        </div>}

        <div className="sidebar-bottom">
          <div className="phase-card">
          <div className="phase-top"><span>CURRENT PHASE</span><span className="phase-number">07 / 09</span></div>
            <div className="phase-state"><i />IMPLEMENTING</div>
          <strong>Voice briefings</strong>
          <small>ElevenLabs · incident-based</small>
          </div>
          <div className="profile-row"><span className="profile-avatar">S</span><span><strong>Demo operator</strong><small>Local session</small></span></div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumbs"><span>Sentinel</span><span className="crumb-slash">/</span><strong>{page === 'overview' ? 'Overview' : page === 'tools' ? 'Tool registry' : page === 'lineage' ? 'Lineage' : page === 'policies' ? 'Policies' : page === 'risk' ? 'Risk & drift' : 'Approvals'}</strong></div>
          <div className="topbar-actions">
            <span className={classNames('connection-pill', online && 'is-online', overview && !online && 'is-degraded', !overview && 'is-pending')}>
              <span className="connection-dot" />{loading && !overview ? 'Connecting' : online ? 'Gateway online' : overview ? 'Degraded' : 'API offline'}
            </span>
            <button className="theme-toggle" onClick={() => setTheme((current) => current === 'dark' ? 'light' : 'dark')} aria-pressed={theme === 'light'} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`} title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}>
              {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
            </button>
            <a className="icon-button docs-link" href="http://127.0.0.1:8000/docs" target="_blank" rel="noreferrer" aria-label="Open API docs" title="Open API docs"><ExternalLink size={16} /></a>
          </div>
        </header>

        <div className="page-content">
          {visibleError && <div className="alert-banner" role="status"><CircleAlert size={16} /><span>{visibleError}</span><button onClick={() => void refresh()} aria-label="Retry connection"><RefreshCw size={15} />Retry</button></div>}
          {postureError && <div className="alert-banner posture-alert" role="status"><CircleAlert size={16} /><span>{postureError}</span><button onClick={() => setPostureError(null)} aria-label="Dismiss drift message"><XCircle size={15} />Dismiss</button></div>}
          {page === 'overview' ? (
            <OverviewPage
              overview={overview}
              serverByName={serverByName}
              events={events}
              journey={journey}
              selectedEvent={selectedEvent}
              running={running}
              resetting={resetting}
              resetCounter={resetCounter}
              onRun={runJourney}
              onReset={resetDemo}
              onInspectEvent={setSelectedEvent}
              onCloseIncident={() => setSelectedEvent(null)}
              lastUpdated={lastUpdated}
              apiOnline={Boolean(overview)}
              voiceAvailable={Boolean(voiceStatus?.available)}
            />
          ) : page === 'tools' ? (
            <ToolsPage tools={tools} servers={overview?.servers ?? []} apiOnline={Boolean(overview)} selectedTool={selectedTool} />
          ) : page === 'lineage' ? (
            <LineagePage journey={journey} />
          ) : page === 'policies' ? (
            <PoliciesPage policies={policies} />
          ) : page === 'risk' ? (
            <RiskPage posture={posture} apiOnline={Boolean(overview)} busy={postureAction} onApproveBaseline={approveToolBaseline} onToggleSimulation={toggleDriftDemo} />
          ) : (
            <ApprovalsPage actions={approvals} token={approverToken} onTokenChange={setApproverToken} busy={approvalBusy} error={approvalError} onApprove={approveAction} onDeny={denyAction} onExecute={executeAction} />
          )}
          <footer className="page-footer">
            <span><span className="footer-pulse" />MCP Sentinel <span className="footer-dot">·</span> Phase 7 incident voice</span>
            <span>Built for a controlled local environment</span>
          </footer>
        </div>
      </main>
    </div>
  )
}

function OverviewPage({
  overview,
  serverByName,
  events,
  journey,
  selectedEvent,
  running,
  resetting,
  resetCounter,
  onRun,
  onReset,
  onInspectEvent,
  onCloseIncident,
  lastUpdated,
  apiOnline,
  voiceAvailable,
}: {
  overview: Overview | null
  serverByName: Map<string, ServerStatus>
  events: SecurityEvent[]
  journey: JourneyResult | null
  selectedEvent: SecurityEvent | null
  running: boolean
  resetting: boolean
  resetCounter: number
  onRun: (scenario: Scenario) => void
  onReset: () => void
  onInspectEvent: (event: SecurityEvent) => void
  onCloseIncident: () => void
  lastUpdated: Date | null
  apiOnline: boolean
  voiceAvailable: boolean
}) {
  const [verdictFilter, setVerdictFilter] = useState<'ALL' | 'ALLOW' | 'WARN' | 'ASK' | 'BLOCK'>('ALL')
  const [labelFilter, setLabelFilter] = useState<'ALL' | SecurityEvent['object_label']>('ALL')
  const [eventSearch, setEventSearch] = useState('')
  useEffect(() => {
    setVerdictFilter('ALL')
    setLabelFilter('ALL')
    setEventSearch('')
  }, [resetCounter])
  const filterCounts = events.reduce<Record<string, number>>((counts, event) => {
    counts[event.decision.verdict] = (counts[event.decision.verdict] ?? 0) + 1
    return counts
  }, {})
  const filteredEvents = events.filter((event) => {
    if (verdictFilter !== 'ALL' && event.decision.verdict !== verdictFilter) return false
    if (labelFilter !== 'ALL' && event.object_label !== labelFilter) return false
    const query = eventSearch.trim().toLowerCase()
    if (!query) return true
    return [event.tool, event.server, event.trace_id, event.session_id, event.object_id ?? '', event.destination ?? '', event.decision.policy_id]
      .some((value) => value.toLowerCase().includes(query))
  })
  const hasActiveEventFilters = verdictFilter !== 'ALL' || labelFilter !== 'ALL' || eventSearch.length > 0

  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow"><span className="eyebrow-line" />MCP SECURITY GATEWAY</div>
          <h1>The agent gets <em>one</em> controlled path.</h1>
          <p>Deterministic decisions before forwarding. One trace from request to sink outcome.</p>
        </div>
        <div className="heading-side">
          <div className="live-clock"><span className={classNames('live-indicator', apiOnline && 'live')} />{apiOnline ? 'LIVE CONNECTION' : 'WAITING FOR API'}</div>
          <span className="updated-time">{lastUpdated ? `Updated ${timeLabel(lastUpdated.toISOString())}` : 'Waiting for first response'}</span>
        </div>
      </div>

      <div className="metric-grid">
        <MetricCard icon={<Activity size={16} />} label="RECORDED CALLS" value={overview ? String(overview.metrics.calls).padStart(2, '0') : '—'} hint="Live backend events · in memory" tone="green" />
        <MetricCard icon={<ShieldCheck size={16} />} label="BLOCKED" value={overview ? String(overview.metrics.blocked).padStart(2, '0') : '—'} hint="Requests stopped before forwarding" tone="blue" />
        <MetricCard icon={<CircleAlert size={16} />} label="WARN / ASK" value={overview ? String(overview.metrics.warnings).padStart(2, '0') : '—'} hint="Policy warnings and pending verdicts" tone="amber" />
        <MetricCard icon={<Database size={16} />} label="SINK EXECUTIONS" value={overview?.sink ? String(overview.sink.execution_count).padStart(2, '0') : '—'} hint="Reported by the sink process" tone="violet" />
      </div>

      <div className="content-grid">
        <section className="panel topology-panel">
          <div className="panel-header">
            <div><div className="panel-kicker">REQUEST PATH</div><h2>Protected tool chain</h2></div>
            <div className="transport-chip"><Radio size={13} />HTTP <span>→</span> stdio</div>
          </div>
          <div className="topology-stage">
            <div className="topology-caption"><span className="topology-caption-dot" />Demo client → Streamable HTTP gateway → controlled stdio servers</div>
            <div className="path-nodes">
              <PathNode name="Reader" detail="Synthetic source" icon={<Database size={18} />} server={serverByName.get('reader')} />
              <PathConnector />
              <PathNode name="Processor" detail="Derived object" icon={<Layers3 size={18} />} server={serverByName.get('processor')} />
              <PathConnector />
              <PathNode name="Sink" detail="Local receiver" icon={<TerminalSquare size={18} />} server={serverByName.get('sink')} />
            </div>
            <div className="gateway-rail"><span className="rail-dash" /><span className="gateway-symbol"><ShieldCheck size={16} /></span><span className="gateway-title">MCP SENTINEL GATEWAY</span><span className="rail-dash" /></div>
            <div className="path-footnote"><LockKeyhole size={12} /><span>Servers are child processes owned by the gateway. No browser-to-server route.</span></div>
          </div>
          <div className="panel-bottomline"><span><span className="status-pip" />{overview ? `${overview.servers_online} of 3 MCP processes connected` : 'Connecting to MCP processes'}</span><span className="muted-inline">Direct access: <strong>unavailable to browser</strong></span></div>
        </section>

        <section className="panel scenario-panel">
          <div className="panel-header scenario-head">
            <div><div className="panel-kicker">PROVENANCE PROOF <span className="mini-badge">LIVE VERDICT</span></div><h2>Classify, inherit, enforce</h2></div>
            <span className="scenario-orbit"><Workflow size={16} /></span>
          </div>
          <p className="scenario-copy">Follow a data label through transformation to the final policy decision.</p>
          <div className="scenario-sequence"><span>classify</span><ArrowRight size={13} /><span>inherit</span><ArrowRight size={13} /><span>trace</span><ArrowRight size={13} /><span>decide</span></div>
          <div className="scenario-actions">
            <button className="run-button" onClick={() => onRun('public_to_approved_sink')} disabled={running || resetting || !overview || overview.servers_online !== 3 || Boolean(overview.policy_error)}>
              {running ? <LoaderCircle className="spin" size={16} /> : <Play size={14} fill="currentColor" />}
              {running ? 'Evaluating policy' : 'Public data · ALLOW'}
            </button>
            <button className="run-button inheritance-button" onClick={() => onRun('multi_parent_inheritance')} disabled={running || resetting || !overview || overview.servers_online !== 3 || Boolean(overview.policy_error)}>
              <GitBranch size={15} />Mixed sources · inherit CONFIDENTIAL
            </button>
            <button className="run-button block-button" onClick={() => onRun('confidential_to_external_sink')} disabled={running || resetting || !overview || overview.servers_online !== 3 || Boolean(overview.policy_error)}>
              <ShieldCheck size={15} />External delivery · BLOCK
            </button>
            <button className="run-button approval-button" onClick={() => onRun('restricted_to_approved_sink')} disabled={running || resetting || !overview || overview.servers_online !== 3 || Boolean(overview.policy_error)}>
              <LockKeyhole size={15} />Restricted data · ASK
            </button>
            <button className="demo-reset-button" onClick={onReset} title="Demo-only: reset the sink counter, events and lineage" disabled={running || resetting || !overview || overview.servers_online !== 3 || Boolean(overview.policy_error)}>
              {resetting ? <LoaderCircle className="spin" size={14} /> : <RefreshCw size={14} />}
              {resetting ? 'Resetting demo state' : 'Reset demo · local only'}
            </button>
          </div>
          <div className="scenario-note"><CircleAlert size={13} /><span>Labels come from trusted lineage. Incomplete ancestry stays UNKNOWN.</span></div>
        </section>
      </div>

      <VoiceBriefingPanel key={resetCounter} apiOnline={apiOnline} audioAvailable={voiceAvailable} />

      {journey && <ReceiptPanel journey={journey} />}

      <section className="panel activity-panel">
        <div className="panel-header activity-heading">
          <div><div className="panel-kicker">GATEWAY EVENT STREAM <span className="live-data-badge">LIVE · IN-MEMORY</span></div><h2>Recent activity <span className="activity-count">{events.length}</span></h2></div>
          <div className="activity-legend"><span><i className="legend-dot complete" />Allow</span><span><i className="legend-dot failed" />Block</span><span className="redaction"><LockKeyhole size={11} />Arguments redacted</span></div>
        </div>
        <div className="event-filters">
          <div className="verdict-filters" role="group" aria-label="Filter events by verdict">
            {(['ALL', 'BLOCK', 'WARN', 'ASK', 'ALLOW'] as const).map((verdict) => <button key={verdict} className={classNames('filter-chip', verdictFilter === verdict && 'active', verdict.toLowerCase())} onClick={() => setVerdictFilter(verdict)}>{verdict}<span>{verdict === 'ALL' ? events.length : filterCounts[verdict] ?? 0}</span></button>)}
          </div>
          <label className="label-filter"><span>DATA LABEL</span><select value={labelFilter} onChange={(event) => setLabelFilter(event.target.value as typeof labelFilter)}><option value="ALL">All labels</option><option value="PUBLIC">Public</option><option value="INTERNAL">Internal</option><option value="CONFIDENTIAL">Confidential</option><option value="RESTRICTED">Restricted</option><option value="UNKNOWN">Unknown</option></select></label>
          <label className="event-search"><Search size={13} /><input value={eventSearch} onChange={(event) => setEventSearch(event.target.value)} placeholder="Search tool, trace, object, destination…" aria-label="Search gateway events" /></label>
          {hasActiveEventFilters && <button className="filter-clear" onClick={() => { setVerdictFilter('ALL'); setLabelFilter('ALL'); setEventSearch('') }}>Clear filters</button>}
        </div>
        <div className="event-table-wrap">
          <table className="event-table">
            <thead><tr><th>TIME</th><th>TOOL CALL</th><th>DATA LABEL</th><th>SERVER</th><th>TRACE ID</th><th>RESULT</th><th>DURATION</th></tr></thead>
            <tbody>
              {filteredEvents.length ? filteredEvents.map((event) => (
                <tr key={event.event_id} className={selectedEvent?.event_id === event.event_id ? 'selected-event' : undefined}>
                  <td className="time-cell"><Clock3 size={12} />{timeLabel(event.timestamp)}</td>
                  <td><div className="tool-cell"><span className="tool-symbol"><Zap size={13} /></span><span><strong>{event.tool}</strong><small>{event.request_id} · {event.argument_keys.length} args redacted</small></span></div></td>
                  <td><span className={classNames('label-chip', event.object_label.toLowerCase())}>{event.object_label}</span><small className="event-object-id">{event.object_id ?? 'no object ID'}</small></td>
                  <td><span className="server-pill"><span className={classNames('tiny-server-dot', event.downstream_executed === true && 'online', event.outcome === 'blocked' && 'blocked-dot')} />{event.server}</span></td>
                  <td><button className="trace-open" onClick={() => onInspectEvent(event)} title={`Open ${event.tool} incident details`}><code className="trace-code">{event.trace_id}</code><span>Inspect</span></button></td>
                  <td><span className={classNames('result-pill', event.decision.verdict.toLowerCase())}>{event.decision.verdict === 'ALLOW' ? <CheckCircle2 size={12} /> : event.decision.verdict === 'BLOCK' ? <XCircle size={12} /> : <CircleAlert size={12} />}{event.decision.verdict}</span><small className="policy-event-id">{event.decision.policy_id}</small></td>
                  <td className="duration-cell">{event.duration_ms} ms</td>
                </tr>
              )) : (
                <tr><td colSpan={7} className="empty-events"><span className="empty-icon"><Activity size={17} /></span><strong>{apiOnline ? events.length ? 'No events match these filters' : 'No gateway calls yet' : 'Waiting for Sentinel API'}</strong><small>{apiOnline ? events.length ? 'Clear a filter or adjust the search.' : 'Run a scenario to create live MCP events.' : 'Start the backend to load live event data.'}</small></td></tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="activity-footer"><span>Showing {filteredEvents.length} of {events.length} recent events <span className="footer-muted">· in-memory for this run</span></span><span className="event-refresh"><span className="refresh-dot" />Polling every 2.5s</span></div>
      </section>

      {selectedEvent && <IncidentDetailPanel key={selectedEvent.event_id} event={selectedEvent} onClose={onCloseIncident} />}

    </>
  )
}

function VoiceBriefingPanel({ apiOnline, audioAvailable }: { apiOnline: boolean; audioAvailable: boolean }) {
  const [briefing, setBriefing] = useState<VoiceBriefing | null>(null)
  const [audioUrl, setAudioUrl] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const audioRef = useRef<HTMLAudioElement>(null)

  useEffect(() => () => {
    if (audioUrl) URL.revokeObjectURL(audioUrl)
  }, [audioUrl])

  const explainLatestBlock = async () => {
    setLoading(true)
    setError(null)
    audioRef.current?.pause()
    if (audioRef.current) audioRef.current.currentTime = 0
    setAudioUrl(null)
    try {
      const result = await api<VoiceBriefing>('/api/voice/query', {
        method: 'POST',
        body: JSON.stringify({ query: 'explain last blocked event' }),
      })
      setBriefing(result)
      if (result.audio_available) {
        try {
          const audio = await apiAudio('/api/voice/speak', {
            method: 'POST',
            body: JSON.stringify({ event_id: result.event_id }),
          })
          setAudioUrl(URL.createObjectURL(audio))
        } catch (audioError) {
          setError(audioError instanceof Error ? `Text fallback is ready. ${audioError.message}` : 'Text fallback is ready; voice generation failed.')
        }
      }
    } catch (queryError) {
      setError(queryError instanceof Error ? queryError.message : 'No blocked incident briefing is available.')
    } finally {
      setLoading(false)
    }
  }

  const play = () => {
    void audioRef.current?.play().catch(() => setError('The browser could not play the generated audio. The text briefing is still available.'))
  }
  const stop = () => {
    if (audioRef.current) {
      audioRef.current.pause()
      audioRef.current.currentTime = 0
    }
  }

  return (
    <section className="panel voice-briefing-panel" aria-labelledby="voice-briefing-title">
      <div className="voice-briefing-main">
        <span className="voice-icon"><Volume2 size={16} /></span>
        <div className="voice-briefing-copy"><div className="panel-kicker">INCIDENT BRIEFING · ELEVENLABS</div><h2 id="voice-briefing-title">Hear the latest BLOCK explained</h2><p>Uses the incident’s verified label, tool, server, and policy rule. No arguments or payload text are sent.</p></div>
        <span className={classNames('voice-availability', audioAvailable && 'voice-ready')}>{audioAvailable ? 'VOICE CONFIGURED' : 'TEXT FALLBACK'}</span>
      </div>
      <button className="voice-query-button" onClick={() => void explainLatestBlock()} disabled={!apiOnline || loading}>
        {loading ? <LoaderCircle className="spin" size={14} /> : <Volume2 size={14} />}
        {loading ? 'Preparing incident briefing' : 'Explain last blocked event'}
      </button>
      {briefing && <div className="voice-briefing-result"><div><span>INCIDENT {briefing.event_id} · TRACE {briefing.trace_id}</span><strong>{briefing.verdict} · {briefing.policy_id}</strong></div><p>{briefing.text}</p></div>}
      {audioUrl && <div className="voice-playback"><audio ref={audioRef} src={audioUrl} preload="none" aria-label="ElevenLabs incident briefing audio" /><button onClick={play}><Play size={13} fill="currentColor" />Play briefing</button><button className="voice-stop" onClick={stop}><Square size={12} fill="currentColor" />Stop</button></div>}
      {!audioAvailable && <div className="voice-fallback-note">Set <code>ELEVENLABS_API_KEY</code> on the backend to enable speech. The generated text explanation works without it.</div>}
      {error && <div className="voice-error" role="status"><CircleAlert size={13} /><span>{error}</span></div>}
    </section>
  )
}

function MetricCard({ icon, label, value, hint, tone }: { icon: React.ReactNode; label: string; value: string; hint: string; tone: string }) {
  return <div className="metric-card"><div className={classNames('metric-icon', tone)}>{icon}</div><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-hint">{hint}</div></div>
}

function PathNode({ name, detail, icon, server }: { name: string; detail: string; icon: React.ReactNode; server?: ServerStatus }) {
  return (
    <div className={classNames('path-node', server?.status === 'online' && 'node-online', server?.status === 'offline' && 'node-offline')}>
      <div className="node-icon-wrap">{icon}<span className="node-health"><span /></span></div>
      <div className="node-name">{name}</div><div className="node-detail">{detail}</div>
      <div className="node-status"><span className={classNames('node-status-dot', server?.status === 'online' && 'online')} />{server?.status === 'online' ? 'ONLINE' : server?.status === 'offline' ? 'OFFLINE' : 'CONNECTING'}</div>
    </div>
  )
}

function PathConnector() {
  return <div className="path-connector"><span /><ArrowRight size={14} /></div>
}

function ReceiptPanel({ journey }: { journey: JourneyResult }) {
  const [copied, setCopied] = useState(false)
  const blocked = journey.verdict === 'BLOCK'
  const pending = journey.verdict === 'ASK'
  const warned = journey.verdict === 'WARN'
  const copyTrace = async () => {
    try {
      await navigator.clipboard.writeText(journey.trace_id)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1400)
    } catch {
      setCopied(false)
    }
  }
  return (
    <>
      <section className={classNames('receipt-panel', blocked && 'blocked-receipt', warned && 'warned-receipt', pending && 'pending-receipt')}>
        <div className="receipt-success"><span className="receipt-check">{blocked ? <XCircle size={16} /> : pending || warned ? <CircleAlert size={16} /> : <Check size={16} />}</span><span><strong>{blocked ? 'Request blocked before forwarding' : pending ? 'Approval required before forwarding' : warned ? 'Delivered with policy warning' : 'Request allowed'}</strong><small>{journey.message}</small></span></div>
        <div className="receipt-divider" />
        <div className="receipt-field trace-field"><span>TRACE ID</span><button onClick={() => void copyTrace()} title="Copy trace ID"><code>{journey.trace_id}</code>{copied ? <Check size={13} /> : <Fingerprint size={13} />}</button></div>
        <div className="receipt-field"><span>POLICY</span><strong>{journey.decision.policy_version}</strong><code>{journey.decision.policy_id}</code></div>
        <div className="receipt-field"><span>SINK COUNTER</span><strong>{journey.sink_execution_before} → {journey.sink_execution_after}</strong><code>{blocked || pending ? 'unchanged · no sink call' : `receipt #${journey.receipt?.execution_count}`}</code></div>
        {journey.receipt && <div className="receipt-field"><span>RECEIPT HASH</span><code>{journey.receipt.payload_sha256.slice(0, 12)}…</code></div>}
        <div className="receipt-reason"><span>{journey.verdict}</span>{journey.decision.reasons[0]}</div>
        {journey.pending_approval && <div className="approval-created"><LockKeyhole size={14} /><span><strong>Pending action {journey.pending_approval.action_id}</strong><small>Expires at {timeLabel(journey.pending_approval.expires_at)} · Open Approvals to review this sanitized request.</small></span></div>}
      </section>
      <LineageGraphPanel graph={journey.lineage} />
    </>
  )
}

function LineagePage({ journey }: { journey: JourneyResult | null }) {
  return (
    <>
      <div className="page-heading tools-page-heading">
        <div><div className="eyebrow"><span className="eyebrow-line" />OBJECT PROVENANCE</div><h1>Lineage explorer<span className="heading-period">.</span></h1><p>Follow trusted source labels through transformations to the attempted destination.</p></div>
        {journey && <a className="registry-summary lineage-api-link" href={`http://127.0.0.1:8000/api/lineage/${encodeURIComponent(journey.trace_id)}`} target="_blank" rel="noreferrer"><span className="registry-summary-icon"><ExternalLink size={17} /></span><span><strong>Trace {journey.trace_id}</strong><small>Open lineage API response</small></span></a>}
      </div>
      {journey ? <LineageGraphPanel graph={journey.lineage} /> : (
        <section className="panel lineage-empty"><GitBranch size={22} /><strong>No lineage trace yet</strong><span>Run one of the scenarios on Overview to create a live source → derived object → destination trace.</span></section>
      )}
    </>
  )
}

function LineageGraphPanel({ graph }: { graph: LineageGraph }) {
  const dataNodes = graph.nodes.filter((node) => node.kind === 'data_object')
  const sources = dataNodes.filter((node) => !node.parent_ids?.length)
  const derived = dataNodes.filter((node) => Boolean(node.parent_ids?.length))
  const destinations = graph.nodes.filter((node) => node.kind === 'destination')
  const labelClass = (label?: string) => (label ?? 'unknown').toLowerCase()

  return (
    <section className="panel lineage-panel">
      <div className="panel-header"><div><div className="panel-kicker">TRACE {graph.trace_id}</div><h2>Data lineage</h2></div><span className="activity-count">{graph.edges.length} links</span></div>
      <div className="lineage-lanes">
        <div className="lineage-lane"><div className="lineage-lane-title">TRUSTED SOURCES <span>{sources.length}</span></div><div className="lineage-card-list">{sources.map((node) => <article className="lineage-node" key={node.object_id}><span className={classNames('label-chip', labelClass(node.label))}>{node.label}</span><strong>{node.source_tool} source</strong><code>{node.object_id}</code><small>{node.source}</small></article>)}</div></div>
        <div className="lineage-flow-arrow"><ArrowRight size={18} /><small>transformed</small></div>
        <div className="lineage-lane"><div className="lineage-lane-title">DERIVED OBJECTS <span>{derived.length}</span></div><div className="lineage-card-list">{derived.map((node) => <article className="lineage-node derived" key={node.object_id}><span className={classNames('label-chip', labelClass(node.label))}>{node.label}</span><strong>{node.transformation ?? 'Unknown transformation'}</strong><code>{node.object_id}</code><small>{node.parent_ids?.length ?? 0} parent object(s): {node.parent_ids?.join(', ') || 'none'}</small><small>Lineage confidence · {Math.round((node.lineage_confidence ?? 0) * 100)}%</small></article>)}</div></div>
        <div className="lineage-flow-arrow"><ArrowRight size={18} /><small>evaluated</small></div>
        <div className="lineage-lane"><div className="lineage-lane-title">DESTINATION ATTEMPTS <span>{destinations.length}</span></div><div className="lineage-card-list">{destinations.map((node) => <article className={classNames('lineage-node', node.verdict === 'BLOCK' && 'destination-blocked')} key={node.destination_id}><span className={classNames('label-chip', labelClass(node.label))}>{node.label}</span><strong>{node.verdict} · {node.downstream_executed === false ? 'not forwarded' : node.downstream_executed === true ? 'forwarded' : 'outcome unknown'}</strong><code>{node.destination}</code><small>{node.reason}</small></article>)}</div></div>
      </div>
      <div className="lineage-footer"><span><GitBranch size={13} />{graph.edges.filter((edge) => edge.relation === 'derived_from').length} parent link(s)</span><span>Labels come from trusted fixture metadata and gateway lineage state.</span></div>
    </section>
  )
}

function IncidentDetailPanel({ event, onClose }: { event: SecurityEvent; onClose: () => void }) {
  const [lineage, setLineage] = useState<LineageGraph | null>(null)
  const [lineageLoading, setLineageLoading] = useState(true)
  const [lineageError, setLineageError] = useState<string | null>(null)
  useEffect(() => {
    let active = true
    setLineage(null)
    setLineageError(null)
    setLineageLoading(true)
    api<LineageGraph>(`/api/lineage/${encodeURIComponent(event.trace_id)}`)
      .then((result) => { if (active) setLineage(result) })
      .catch((error) => { if (active) setLineageError(error instanceof Error ? error.message : 'Lineage is unavailable for this event.') })
      .finally(() => { if (active) setLineageLoading(false) })
    return () => { active = false }
  }, [event.trace_id])

  const executionLabel = event.downstream_executed === false
    ? 'Not executed · blocked before forwarding'
    : event.downstream_executed === true
      ? 'Executed downstream'
      : 'Outcome unknown'

  return (
    <>
      <section className="panel incident-detail" aria-labelledby="incident-detail-title">
        <div className="panel-header incident-detail-header">
          <div><div className="panel-kicker">INCIDENT DETAIL · {timeLabel(event.timestamp)}</div><h2 id="incident-detail-title">{event.tool} <span className={classNames('result-pill', event.decision.verdict.toLowerCase())}>{event.decision.verdict}</span></h2></div>
          <button className="incident-close" onClick={onClose}>Close</button>
        </div>
        <div className="incident-facts">
          <div className="incident-fact"><span>OBJECT &amp; LABEL</span><strong>{event.object_label}</strong><code>{event.object_id ?? 'No object ID'}</code>{event.parent_object_ids.length > 0 && <small>Parents: {event.parent_object_ids.join(', ')}</small>}</div>
          <div className="incident-fact"><span>DESTINATION</span><strong>{event.destination ?? event.decision.normalized_destination ?? 'No destination on this call'}</strong><small>{executionLabel}</small></div>
          <div className="incident-fact"><span>POLICY</span><strong>{event.decision.policy_id}</strong><small>Version {event.decision.policy_version}</small></div>
          <div className="incident-fact"><span>TRACE · SESSION</span><strong>{event.trace_id}</strong><small>{event.session_id}</small></div>
        </div>
        <div className={classNames('incident-reason', event.decision.verdict.toLowerCase())}><span>MATCHED REASON</span><p>{event.decision.reasons.join(' ')}</p></div>
        <div className="incident-evidence"><span>DOWNSTREAM EVIDENCE</span><strong>{executionLabel}</strong><small>Event {event.event_id} · {event.duration_ms} ms · {event.argument_keys.length} argument names only</small></div>
        {lineageLoading && <div className="incident-lineage-message">Loading trace lineage…</div>}
        {lineageError && <div className="incident-lineage-message">{lineageError}</div>}
      </section>
      {lineage && <LineageGraphPanel graph={lineage} />}
    </>
  )
}

function RiskPage({
  posture,
  apiOnline,
  busy,
  onApproveBaseline,
  onToggleSimulation,
}: {
  posture: SecurityPosture | null
  apiOnline: boolean
  busy: boolean
  onApproveBaseline: () => void
  onToggleSimulation: (enabled: boolean) => void
}) {
  const drift = posture?.drift
  const risk = posture?.risk
  const reviewItems = drift?.items.filter((item) => ['changed', 'added', 'removed', 'unbaselined'].includes(item.status)) ?? []
  const summary = drift?.summary

  return (
    <>
      <div className="page-heading tools-page-heading">
        <div><div className="eyebrow"><span className="eyebrow-line" />INTEGRITY &amp; EXPLAINABLE SIGNALS</div><h1>Risk &amp; drift<span className="heading-period">.</span></h1><p>Compare discovered tool contracts with an approved snapshot and explain every risk point.</p></div>
        <div className="registry-summary risk-heading-summary"><span className="registry-summary-icon"><Fingerprint size={17} /></span><span><strong>{drift?.baseline_status === 'active' ? `${summary?.unchanged ?? 0} matching` : drift?.baseline_status === 'error' ? 'Baseline error' : 'Baseline needed'}</strong><small>{drift?.approved_at ? `Approved ${timeLabel(drift.approved_at)}` : 'No approved fingerprint set'}</small></span></div>
      </div>

      <section className="panel risk-panel">
        <div className="panel-header"><div><div className="panel-kicker">EXPLAINABLE RISK · OBSERVATION ONLY</div><h2>Current risk factors</h2></div><span className={classNames('risk-level', risk?.level.toLowerCase())}>{risk?.level ?? 'WAITING'}</span></div>
        <div className="risk-summary-row">
          <div className="risk-score-block"><div className="risk-score"><strong>{risk?.score ?? '—'}</strong><span>/ 100</span></div><div className="risk-meter" role="meter" aria-label="Explainable risk score" aria-valuemin={0} aria-valuemax={100} aria-valuenow={risk?.score ?? 0}><span style={{ width: `${risk?.score ?? 0}%` }} /></div><small>{risk?.scope ?? 'Waiting for the Sentinel API'}</small></div>
          <div className="risk-policy-note"><ShieldCheck size={18} /><span><strong>Policy remains authoritative</strong><small>{risk?.policy_note ?? 'Risk never replaces deterministic policy decisions.'}</small></span></div>
        </div>
        <div className="risk-factor-grid">
          {(risk?.factors ?? []).map((factor) => <article className={classNames('risk-factor', factor.active && 'factor-active')} key={factor.id}><div><strong>{factor.title}</strong><span className="risk-points">{factor.active ? `+${factor.points}` : '0'} pts</span></div><p>{factor.explanation}</p></article>)}
          {!risk && <div className="posture-empty">Risk factors will appear when the API is connected.</div>}
        </div>
        <div className="risk-method-note">Fixed points: labels INTERNAL 7 / CONFIDENTIAL 18 / RESTRICTED 28 / UNKNOWN 12; external or invalid destination 20; tool capability read 4 / summarize 8 / deliver 12 / sink status or reset 2 / unknown tool 16; missing lineage 18; drift or missing approval 25; volume 12 at 5+ calls per tool in 60s; sensitive transform-to-delivery pattern 15. Uses the latest 20 events, caps at 100. Bands: Low 0–24 · Guarded 25–49 · Elevated 50–74 · Critical 75–100.</div>
      </section>

      <section className="panel drift-panel">
        <div className="panel-header drift-header"><div><div className="panel-kicker">APPROVED TOOL CONTRACTS</div><h2>Tool drift review</h2></div><span className={classNames('drift-status', drift?.drift_detected && 'has-drift', drift?.baseline_status === 'missing' && 'needs-baseline')}>{drift?.baseline_status === 'error' ? 'BASELINE ERROR' : drift?.baseline_status === 'active' ? drift.drift_detected ? 'REVIEW REQUIRED' : 'INTEGRITY MATCH' : 'BASELINE REQUIRED'}</span></div>
        {drift?.baseline_error && <div className="drift-inline-error">{drift.baseline_error}</div>}
        {drift?.demo_simulation && <div className="simulation-banner"><CircleAlert size={15} /><span><strong>SIMULATED DRIFT</strong> · Seeded fixture only; the live MCP tool and its execution schema are unchanged.</span></div>}
        <div className="drift-toolbar">
          <div className="drift-counts">
            <span><strong>{summary?.unchanged ?? 0}</strong> match</span><span><strong>{summary?.changed ?? 0}</strong> changed</span><span><strong>{summary?.added ?? 0}</strong> new</span><span><strong>{summary?.removed ?? 0}</strong> missing</span>
          </div>
          <div className="drift-actions">
            <button className="drift-button primary" onClick={onApproveBaseline} disabled={!apiOnline || busy || drift?.discovery_status !== 'ready' || drift?.demo_simulation} title={drift?.baseline_status === 'active' ? 'Capture a new approved snapshot from the live tool registry' : 'Save the connected tool definitions as the approved baseline'}>
              {busy ? <LoaderCircle className="spin" size={14} /> : <Fingerprint size={14} />}{drift?.baseline_status === 'active' ? 'Update approved baseline' : 'Approve current definitions'}
            </button>
            <button className="drift-button" onClick={() => onToggleSimulation(!drift?.demo_simulation)} disabled={!apiOnline || busy || drift?.baseline_status !== 'active'} title="Show a seeded schema and description change without changing the running MCP server">
              {busy ? <LoaderCircle className="spin" size={14} /> : <Code2 size={14} />}{drift?.demo_simulation ? 'Clear simulation' : 'Simulate seeded drift'}
            </button>
          </div>
        </div>
        {drift?.discovery_status === 'waiting' && <div className="posture-empty">Waiting for all three controlled MCP servers before comparing tool definitions.</div>}
        {drift?.baseline_status === 'missing' && drift.discovery_status === 'ready' && <div className="baseline-empty"><Fingerprint size={19} /><strong>Capture the first approved snapshot</strong><span>Sentinel fingerprints each discovered tool name, description, and JSON input schema. The snapshot is saved locally and reused after restart.</span></div>}
        {drift?.baseline_status === 'active' && reviewItems.length > 0 && <div className="drift-item-list">
          {reviewItems.map((item) => <article className={classNames('drift-item', `drift-${item.status}`)} key={item.name}>
            <div className="drift-item-heading"><span><strong>{item.name}</strong><small>{item.server} · approved {item.approved_fingerprint?.slice(0, 12) ?? '—'} · discovered {item.current_fingerprint?.slice(0, 12) ?? '—'} · SHA-256</small></span><span className={classNames('drift-item-status', `status-${item.status}`)}>{item.status === 'changed' ? 'CHANGED' : item.status === 'added' ? 'NEW TOOL' : item.status === 'removed' ? 'MISSING' : 'UNBASELINED'}</span></div>
            {item.changes.length > 0 ? <div className="drift-changes">{item.changes.map((change, index) => <div className="drift-change" key={`${change.path}-${index}`}><strong>{change.path}</strong><span className={`change-kind ${change.kind}`}>{change.kind}</span><div className="change-values">{change.before !== null && <code><i>Approved</i>{change.before}</code>}{change.after !== null && <code><i>Discovered</i>{change.after}</code>}</div></div>)}</div> : <p className="drift-item-note">No approved baseline exists for this tool yet.</p>}
          </article>)}
        </div>}
        {drift?.baseline_status === 'active' && drift.discovery_status === 'ready' && !drift.drift_detected && <div className="drift-clear-state"><CheckCircle2 size={18} /><span><strong>All {summary?.unchanged ?? 0} discovered tools match.</strong><small>Fingerprints cover the canonical name, description, and input schema.</small></span></div>}
        <div className="drift-footnote"><span>Approved snapshot is stored in the local project configuration.</span><span>{drift?.demo_simulation ? 'Fixture overlays summarize_document only.' : 'Demo drift is disabled.'}</span></div>
      </section>
    </>
  )
}

function ApprovalsPage({
  actions,
  token,
  onTokenChange,
  busy,
  error,
  onApprove,
  onDeny,
  onExecute,
}: {
  actions: ApprovalAction[]
  token: string
  onTokenChange: (value: string) => void
  busy: boolean
  error: string | null
  onApprove: (actionId: string, rationale: string) => void
  onDeny: (actionId: string, rationale: string) => void
  onExecute: (actionId: string) => void
}) {
  const pendingCount = actions.filter((action) => action.status === 'pending').length
  return (
    <>
      <div className="page-heading tools-page-heading">
        <div><div className="eyebrow"><span className="eyebrow-line" />CONTROLLED EXCEPTIONS</div><h1>Approvals<span className="heading-period">.</span></h1><p>Review a sanitized ASK request, approve or deny it, then execute its exact bound request once.</p></div>
        <div className="registry-summary"><span className="registry-summary-icon"><LockKeyhole size={17} /></span><span><strong>{pendingCount} pending</strong><small>5 minute expiry · one execution</small></span></div>
      </div>

      <section className="panel approver-access">
        <div className="approver-copy"><strong>Demo approver access</strong><small>Enter the server-configured local token. It stays in this browser session and is sent only with approval actions.</small></div>
        <label><span>APPROVER TOKEN</span><input type="password" autoComplete="off" value={token} onChange={(event) => onTokenChange(event.target.value)} placeholder="Enter demo approver token" /></label>
        <span className="approver-local-note">Local default: <code>sentinel-demo-approver</code> · override with <code>MCP_SENTINEL_APPROVER_TOKEN</code></span>
      </section>
      {error && <div className="approval-error" role="status"><CircleAlert size={15} /><span>{error}</span></div>}

      {actions.length ? <div className="approval-list">
        {actions.map((action) => <ApprovalActionCard key={action.action_id} action={action} token={token} busy={busy} onApprove={onApprove} onDeny={onDeny} onExecute={onExecute} />)}
      </div> : (
        <section className="panel approval-empty"><Clock3 size={22} /><strong>No approval requests</strong><span>Run the restricted fixture from Overview to create a pending local delivery request. It will not reach the sink before approval and execution.</span></section>
      )}
    </>
  )
}

function ApprovalActionCard({
  action,
  token,
  busy,
  onApprove,
  onDeny,
  onExecute,
}: {
  action: ApprovalAction
  token: string
  busy: boolean
  onApprove: (actionId: string, rationale: string) => void
  onDeny: (actionId: string, rationale: string) => void
  onExecute: (actionId: string) => void
}) {
  const [rationale, setRationale] = useState('')
  const canDecide = token.trim().length > 0 && rationale.trim().length >= 4 && !busy
  const statusLabel = action.status === 'pending' ? 'PENDING REVIEW' : action.status.toUpperCase()
  const dateTime = (value: string) => new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
  return (
    <article className={classNames('panel approval-card', `approval-${action.status}`)}>
      <div className="approval-card-heading"><span><strong>{action.action_id}</strong><small>{action.tool_name} · request {action.request_id}</small></span><span className={classNames('approval-status', `approval-status-${action.status}`)}>{statusLabel}</span></div>
      <div className="approval-facts">
        <div><span>DATA LABEL · OBJECT</span><strong><span className={classNames('label-chip', action.data_label.toLowerCase())}>{action.data_label}</span> {action.object_id ?? 'No object ID'}</strong></div>
        <div><span>DESTINATION</span><strong>{action.destination}</strong></div>
        <div><span>POLICY</span><strong>{action.policy_id}</strong><small>Version {action.policy_version}</small></div>
        <div><span>EXPIRY</span><strong>{dateTime(action.expires_at)}</strong><small>Created {dateTime(action.created_at)}</small></div>
      </div>
      <div className="approval-reason"><span>WHY SENTINEL ASKED</span><p>{action.reason}</p></div>
      <div className="approval-preview"><div><span>SANITIZED REQUEST</span><small>{action.argument_names.join(' · ')}</small></div><code>{action.sanitized_arguments.payload}</code><code>Trace {action.trace_id} · SHA-256 {action.payload_sha256.slice(0, 16)}…</code></div>
      <div className="approval-binding"><span>CANONICAL REQUEST HASH</span><code>{action.request_hash}</code></div>
      {action.status === 'pending' && <div className="approval-controls"><label><span>RATIONALE · REQUIRED</span><input value={rationale} onChange={(event) => setRationale(event.target.value)} maxLength={240} minLength={4} placeholder="Why approve or deny this exact request?" /></label><div><button className="approval-deny-button" disabled={!canDecide} onClick={() => onDeny(action.action_id, rationale.trim())}><XCircle size={14} />Deny</button><button className="approval-allow-button" disabled={!canDecide} onClick={() => onApprove(action.action_id, rationale.trim())}><Check size={14} />Approve exact request</button></div></div>}
      {action.status === 'approved' && <div className="approval-approved-row"><span><CheckCircle2 size={14} />Approved by {action.approver_id} · {action.decision_at ? dateTime(action.decision_at) : ''}<small>{action.rationale}</small></span><button className="approval-allow-button" disabled={!token.trim() || busy} onClick={() => onExecute(action.action_id)}><Play size={13} fill="currentColor" />Re-check policy &amp; execute once</button></div>}
      {action.status === 'denied' && <div className="approval-terminal-row denied"><XCircle size={14} /><span>Denied by {action.approver_id} · {action.rationale} · downstream was not executed.</span></div>}
      {action.status === 'executed' && <div className="approval-terminal-row executed"><CheckCircle2 size={14} /><span>Executed by {action.executed_by} · {action.receipt ? `sink receipt #${action.receipt.execution_count}` : 'receipt metadata unavailable'} · {action.receipt?.payload_sha256 ? `SHA-256 ${action.receipt.payload_sha256.slice(0, 16)}…` : 'no receipt hash'}.</span></div>}
      {['expired', 'failed'].includes(action.status) && <div className="approval-terminal-row denied"><CircleAlert size={14} /><span>{action.last_error ?? `Request ${action.status}; it cannot execute.`}</span></div>}
      {action.status === 'executing' && <div className="approval-terminal-row"><LoaderCircle className="spin" size={14} /><span>Re-evaluating policy and executing the exact request…</span></div>}
    </article>
  )
}

function PoliciesPage({ policies }: { policies: PolicySet | null }) {
  return (
    <>
      <div className="page-heading tools-page-heading">
        <div><div className="eyebrow"><span className="eyebrow-line" />DETERMINISTIC POLICY</div><h1>Policy control<span className="heading-period">.</span></h1><p>Backend-owned rules run before any downstream MCP call.</p></div>
        <div className="registry-summary"><span className="registry-summary-icon"><LockKeyhole size={17} /></span><span><strong>{policies?.status === 'active' ? `v${policies.version}` : 'Unavailable'}</strong><small>{policies?.policy_id ?? 'policy engine status'}</small></span></div>
      </div>
      {!policies || policies.status !== 'active' ? <div className="registry-banner"><CircleAlert size={17} /><strong>Policy engine unavailable — gateway calls fail closed.</strong></div> : (
        <>
          <div className="registry-banner"><div className="registry-banner-icon"><ShieldCheck size={17} /></div><div><strong>Policy evaluation is server-side and deterministic</strong><p>A BLOCK is recorded with a rule ID, version, reason, and proof that forwarding did not occur.</p></div><span className="registry-protocol">{policies.policy_id}</span></div>
          <div className="panel policy-rules-panel">
            <div className="panel-header"><div><div className="panel-kicker">RULE ORDER</div><h2>Active policy rules</h2></div><span className="activity-count">{policies.rules?.length ?? 0}</span></div>
            <div className="policy-rule-list">{(policies.rules ?? []).map((rule) => <div className="policy-rule" key={rule.id}><span className="policy-priority">{String(rule.priority).padStart(2, '0')}</span><span className={classNames('rule-effect', rule.effect.toLowerCase())}>{rule.effect}</span><span className="rule-main"><strong>{rule.title}</strong><small>{rule.id}</small></span></div>)}</div>
          </div>
          <div className="policy-config-grid">
            <section className="panel policy-config-card"><div className="panel-kicker">TRUSTED DESTINATIONS</div>{(policies.trusted_destinations ?? []).map((destination) => <code key={destination}>{destination}</code>)}</section>
            <section className="panel policy-config-card"><div className="panel-kicker">AGENT PERMISSIONS</div>{Object.entries(policies.agents ?? {}).map(([agent, access]) => <div className="agent-permission" key={agent}><strong>{agent}</strong><span>{access.allow.join(', ')}</span></div>)}</section>
          </div>
          <div className="registry-footnote"><ShieldCheck size={14} /><span>Unknown lineage to an external destination is configured as {policies.unknown_lineage_external_verdict}. Restricted data gets an ASK; forwarding still requires a fresh policy check and a one-time exact-request approval.</span></div>
        </>
      )}
    </>
  )
}

function ToolsPage({ tools, servers, apiOnline, selectedTool }: { tools: ToolDefinition[]; servers: ServerStatus[]; apiOnline: boolean; selectedTool: ToolDefinition | null }) {
  const [expandedTool, setExpandedTool] = useState<string | null>(selectedTool?.name ?? null)
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({ reader: true, processor: true, sink: true })
  useEffect(() => {
    if (selectedTool) {
      setExpandedTool(selectedTool.name)
      setExpandedGroups((current) => current[selectedTool.server] ? current : { ...current, [selectedTool.server]: true })
    }
  }, [selectedTool])
  const statusMap = new Map(servers.map((server) => [server.name, server]))
  const grouped = ['reader', 'processor', 'sink'].map((name) => ({
    name,
    tools: tools.filter((tool) => tool.server === name),
    server: statusMap.get(name),
  }))

  return (
    <>
      <div className="page-heading tools-page-heading">
        <div><div className="eyebrow"><span className="eyebrow-line" />MCP DISCOVERY</div><h1>Tool registry<span className="heading-period">.</span></h1><p>Live tool definitions discovered from the controlled MCP servers.</p></div>
        <div className="registry-summary"><span className="registry-summary-icon"><Boxes size={17} /></span><span><strong>{apiOnline ? tools.length : '—'} tools</strong><small>loaded from connected servers</small></span></div>
      </div>
      <div className="registry-banner"><div className="registry-banner-icon"><Network size={17} /></div><div><strong>Registry sourced from MCP discovery</strong><p>Sentinel lists each tool and input schema from its live stdio client connection. The browser does not call these servers directly.</p></div><span className="registry-protocol"><Radio size={13} />stdio transport</span></div>
      <div className="registry-groups">
        {grouped.map(({ name, tools: serverTools, server }) => (
          <section className="panel registry-group" key={name}>
            <button className="registry-group-head" onClick={() => setExpandedGroups((current) => ({ ...current, [name]: !current[name] }))} aria-expanded={expandedGroups[name]} aria-controls={`registry-tools-${name}`}>
              <span className="registry-server-icon"><ServerIcon name={name} /></span><span className="registry-server-title"><span className="registry-server-heading"><span className="registry-server-name">{name}</span><span className={classNames('server-health-label', server?.status === 'online' ? 'health-online' : 'health-offline')}><i />{server?.status === 'online' ? 'Connected' : server?.status === 'offline' ? 'Offline' : 'Waiting'}</span></span><span className="registry-server-description">{server?.display_name ?? `${name} MCP server`} <i>·</i> {server?.transport ?? 'stdio'} <i>·</i> {server?.tools_count ?? serverTools.length} discovered {server?.tools_count === 1 ? 'tool' : 'tools'}</span></span><span className="group-count">{String(serverTools.length).padStart(2, '0')}</span><ChevronDown className={classNames('registry-group-chevron', expandedGroups[name] && 'expanded')} size={16} />
            </button>
            <div className="registry-tool-list" id={`registry-tools-${name}`} hidden={!expandedGroups[name]}>
              {serverTools.length ? serverTools.map((tool) => (
                <div className="registry-tool" key={tool.name}>
                  <button className="registry-tool-row" onClick={() => setExpandedTool(expandedTool === tool.name ? null : tool.name)} aria-expanded={expandedTool === tool.name}>
                    <span className="registry-tool-terminal"><Code2 size={14} /></span><span className="registry-tool-main"><strong>{tool.name}</strong><small>{tool.title ?? tool.description}</small></span><span className="schema-label">INPUT SCHEMA</span><ChevronDown className={classNames('schema-chevron', expandedTool === tool.name && 'expanded')} size={15} />
                  </button>
                  {expandedTool === tool.name && <div className="schema-content"><div className="schema-description">{tool.description}</div><pre>{JSON.stringify(tool.input_schema, null, 2)}</pre></div>}
                </div>
              )) : <div className="registry-empty">{server?.error ?? 'No tool definitions available yet.'}</div>}
            </div>
          </section>
        ))}
      </div>
      <div className="registry-footnote"><ShieldCheck size={14} /><span>Live discovery feeds the approved-fingerprint comparison on Risk &amp; drift. The simulation never changes this executable registry.</span></div>
    </>
  )
}

function ServerIcon({ name }: { name: string }) {
  if (name === 'reader') return <Database size={17} />
  if (name === 'processor') return <Layers3 size={17} />
  return <TerminalSquare size={17} />
}

export default App
