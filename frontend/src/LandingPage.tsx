import { lazy, Suspense, useRef } from 'react'
import SentinelMark from './SentinelMark'
import {
  ArrowDown,
  ArrowRight,
  ArrowUpRight,
  AudioLines,
  Check,
  ChevronRight,
  GitBranch,
  LockKeyhole,
  Orbit,
  Radar,
  ShieldCheck,
  Sun,
  Moon,
  Waypoints,
} from 'lucide-react'
import { motion, useReducedMotion, useScroll, useSpring, useTransform } from 'motion/react'

const SentinelScene = lazy(() => import('./SentinelScene'))

type LandingPageProps = {
  apiStatus: 'online' | 'degraded' | 'offline'
  theme: 'dark' | 'light'
  onToggleTheme: () => void
  onOpenConsole: () => void
}

const controls = [
  {
    index: '01',
    icon: LockKeyhole,
    title: 'Policy before forwarding',
    detail: 'Every tool call meets a deterministic decision before a downstream server sees it.',
    signal: 'PRE-FORWARD GATE',
    tone: 'lime',
  },
  {
    index: '02',
    icon: GitBranch,
    title: 'Lineage that follows the data',
    detail: 'Parent labels carry through transformations, so a summary keeps its highest sensitivity.',
    signal: 'TRUSTED PROVENANCE',
    tone: 'mint',
  },
  {
    index: '03',
    icon: Radar,
    title: 'A request you can prove',
    detail: 'See the verdict, policy reason, event trail, and sink counter in one local demo.',
    signal: 'VISIBLE EVIDENCE',
    tone: 'blue',
  },
]

function Reveal({ children, className = '', delay = 0 }: { children: React.ReactNode; className?: string; delay?: number }) {
  const reducedMotion = useReducedMotion()
  return (
    <motion.div
      className={className}
      initial={reducedMotion ? false : { opacity: 0, y: 28, filter: 'blur(8px)' }}
      whileInView={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
      viewport={{ once: true, amount: 0.2 }}
      transition={{ duration: reducedMotion ? 0 : 0.72, delay: reducedMotion ? 0 : delay, ease: [0.21, 0.8, 0.22, 1] }}
    >
      {children}
    </motion.div>
  )
}

export default function LandingPage({ apiStatus, theme, onToggleTheme, onOpenConsole }: LandingPageProps) {
  const reducedMotion = useReducedMotion()
  const heroRef = useRef<HTMLElement>(null)
  const { scrollYProgress } = useScroll()
  const scrollProgress = useSpring(scrollYProgress, { stiffness: 90, damping: 26, restDelta: 0.001 })
  const heroY = useTransform(scrollYProgress, [0, 0.5], [0, 88])
  const heroOpacity = useTransform(scrollYProgress, [0, 0.42], [1, 0.12])

  return (
    <main className="landing-shell" id="top">
      <motion.div className="landing-scroll-progress" style={{ scaleX: scrollProgress }} />
      <div className="landing-noise" aria-hidden="true" />
      <header className="landing-nav">
        <button className="landing-brand" onClick={onOpenConsole} aria-label="Open MCP Sentinel console">
          <span className="landing-brand-mark"><SentinelMark /></span>
          <span><strong>Sentinel</strong></span>
        </button>
        <nav aria-label="Landing page navigation">
          <a href="#system">System</a>
          <a href="#controls">Controls</a>
          <a href="#demo">Demo path</a>
        </nav>
        <div className="landing-nav-actions">
          <button className="theme-toggle theme-toggle-landing" onClick={onToggleTheme} aria-pressed={theme === 'light'} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`} title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}>
            {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
          </button>
          <span className={`landing-api-state ${apiStatus === 'online' ? 'is-live' : ''} ${apiStatus === 'degraded' ? 'is-degraded' : ''}`}>
            <i />{apiStatus === 'online' ? 'GATEWAY LIVE' : apiStatus === 'degraded' ? 'GATEWAY DEGRADED' : 'LOCAL API STANDBY'}
          </span>
          <button className="landing-nav-cta" onClick={onOpenConsole}>Open console <ArrowUpRight size={14} /></button>
        </div>
      </header>

      <section className="landing-hero" ref={heroRef} aria-labelledby="landing-title">
        <div className="hero-grid-glow" aria-hidden="true" />
        <div className="hero-copy-wrap">
          <motion.div
            className="hero-copy"
            initial={reducedMotion ? false : { opacity: 0, y: 22 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: reducedMotion ? 0 : 0.75, ease: [0.21, 0.8, 0.22, 1] }}
          >
            <div className="hero-eyebrow"><span className="hero-eyebrow-mark"><Orbit size={12} /></span> SECURITY THAT SITS IN THE PATH <span className="hero-eyebrow-line" /></div>
            <h1 id="landing-title">One trusted path<br />for every <em>agent action.</em></h1>
            <p className="hero-lede">MCP Sentinel checks the call, tracks the data, and stops risky delivery before it reaches a tool.</p>
            <div className="hero-actions">
              <button className="hero-primary" onClick={onOpenConsole}>Enter live console <ArrowRight size={16} /></button>
              <a className="hero-secondary" href="#system"><span><ArrowDown size={14} /></span>See how it works</a>
            </div>
            <div className="hero-proof-row">
              <span><Check size={12} /> DECISIONS BEFORE FORWARDING</span>
              <i />
              <span><Check size={12} /> LOCAL, TRACEABLE DEMO</span>
            </div>
          </motion.div>
        </div>

        <motion.div className="hero-visual" style={reducedMotion ? undefined : { y: heroY, opacity: heroOpacity }}>
          <div className="hero-scene-grid" aria-hidden="true" />
          <div className="scene-orbit-label scene-label-top"><span className="scene-label-dot lime-dot" />POLICY ENGINE <b>ACTIVE</b></div>
          <div className="scene-orbit-label scene-label-bottom"><span className="scene-label-dot blue-dot" />EXTERNAL ROUTE <b>BLOCKED</b></div>
          <div className="scene-ring scene-ring-one" aria-hidden="true" />
          <div className="scene-ring scene-ring-two" aria-hidden="true" />
          <div className="scene-core-wrap" role="img" aria-label="A 3D visualization of the Sentinel policy gateway with requests moving through monitored paths">
            <Suspense fallback={<div className="scene-loading" aria-hidden="true"><span /></div>}>
              <SentinelScene reducedMotion={Boolean(reducedMotion)} />
            </Suspense>
          </div>
          <div className="scene-node node-source"><span className="scene-node-icon"><Waypoints size={14} /></span><span><small>INCOMING TOOL</small><b>summarize_document</b></span><span className="node-status">01</span></div>
          <div className="scene-node node-gate"><span className="scene-node-icon gate-icon"><LockKeyhole size={14} /></span><span><small>POLICY GATE</small><b>CONFIDENTIAL · WARN</b></span><span className="node-signal"><i /></span></div>
          <div className="scene-packet packet-a" aria-hidden="true" />
          <div className="scene-packet packet-b" aria-hidden="true" />
          <div className="scene-caption"><span>LIVE POLICY SIMULATION</span><span className="caption-coordinates">01 : 04 : 22</span></div>
        </motion.div>

        <div className="hero-scroll-cue"><span>SCROLL TO EXPLORE</span><i><ArrowDown size={13} /></i></div>
      </section>

      <section className="landing-signal-strip" aria-label="Sentinel demo capabilities">
        <div><span className="signal-number">03</span><span><b>CONTROLLED SERVERS</b><small>Reader · Processor · Sink</small></span></div>
        <div><span className="signal-number"><GitBranch size={20} /></span><span><b>ONE TRACE PER JOURNEY</b><small>Request to downstream outcome</small></span></div>
        <div><span className="signal-number"><LockKeyhole size={19} /></span><span><b>EXACT REQUEST APPROVAL</b><small>Re-check before one-time execution</small></span></div>
        <div><span className="signal-number"><AudioLines size={20} /></span><span><b>INCIDENT VOICE</b><small>ElevenLabs · optional fallback</small></span></div>
      </section>

      <section className="landing-system-section" id="system" aria-labelledby="system-title">
        <div className="landing-section-header">
          <Reveal className="section-kicker">01 / THE CONTROL PATH</Reveal>
          <Reveal>
            <div className="system-heading-grid">
              <h2 id="system-title">A short path.<br /><em>A hard boundary.</em></h2>
              <p>Every request is mediated by Sentinel. Downstream tools never become the agent’s shortcut around policy.</p>
            </div>
          </Reveal>
        </div>
        <Reveal className="system-flow-card">
          <div className="flow-card-top"><span>REQUEST MEDIATION <i /></span><span>LOCAL DEMO · MCP STREAMABLE HTTP → STDIO</span></div>
          <div className="flow-track" aria-label="Agent to gateway to policy to controlled MCP servers">
            <div className="flow-node agent-flow"><span className="flow-icon"><Waypoints size={18} /></span><small>01 / REQUEST</small><strong>AI agent</strong><span>Tool call + arguments</span></div>
            <div className="flow-connector"><i /><i /><i /><ArrowRight size={14} /></div>
            <div className="flow-node sentinel-flow"><span className="flow-icon"><ShieldCheck size={18} /></span><small>02 / MEDIATE</small><strong>Sentinel gateway</strong><span>Identity · schema · lineage</span></div>
            <div className="flow-connector"><i /><i /><i /><ArrowRight size={14} /></div>
            <div className="flow-node policy-flow"><span className="flow-icon"><LockKeyhole size={18} /></span><small>03 / DECIDE</small><strong>Policy engine</strong><span>ALLOW · WARN · ASK · BLOCK</span></div>
            <div className="flow-connector"><i /><i /><i /><ArrowRight size={14} /></div>
            <div className="flow-node tools-flow"><span className="flow-icon"><Radar size={18} /></span><small>04 / CONTROLLED</small><strong>Reader · Processor · Sink</strong><span>Only approved local tools</span></div>
          </div>
          <div className="flow-card-foot"><span><i className="flow-green-dot" /> POLICY RUNS BEFORE FORWARDING</span><span>Every outcome receives a trace ID <ArrowUpRight size={12} /></span></div>
        </Reveal>
      </section>

      <section className="landing-controls-section" id="controls" aria-labelledby="controls-title">
        <div className="controls-copy">
          <Reveal className="section-kicker">02 / BUILT TO BE INSPECTED</Reveal>
          <Reveal><h2 id="controls-title">Make the invisible<br /><em>part visible.</em></h2></Reveal>
          <Reveal><p>Not another glowing lock. A working demo with observable decisions, real controlled servers, and evidence you can follow.</p></Reveal>
          <Reveal><a className="text-link" href="#demo">Explore the live demo <ChevronRight size={14} /></a></Reveal>
        </div>
        <div className="control-card-grid">
          {controls.map(({ index, icon: Icon, title, detail, signal, tone }, position) => (
            <Reveal key={index} delay={position * 0.1} className={`control-card control-${tone}`}>
              <div className="control-card-top"><span>{index} / CONTROL</span><Icon size={17} /></div>
              <div className="control-card-graphic" aria-hidden="true"><i /><i /><i /><i /><i /><span /></div>
              <h3>{title}</h3>
              <p>{detail}</p>
              <div className="control-card-signal"><span><i />{signal}</span><ArrowUpRight size={13} /></div>
            </Reveal>
          ))}
        </div>
      </section>

      <section className="landing-demo-section" id="demo" aria-labelledby="demo-title">
        <div className="demo-ambient" aria-hidden="true" />
        <Reveal className="demo-card">
          <div className="demo-card-copy">
            <span className="section-kicker">03 / YOUR DEMO STARTS HERE</span>
            <h2 id="demo-title">See the block.<br /><em>Follow the proof.</em></h2>
            <p>Run a benign request, then attempt a sensitive external delivery. Watch Sentinel block it before execution and leave the sink counter unchanged.</p>
            <button className="hero-primary" onClick={onOpenConsole}>Open the live console <ArrowRight size={16} /></button>
          </div>
          <div className="demo-terminal" aria-label="Example blocked incident">
            <div className="terminal-top"><span><i /><i /><i /></span><b>sentinel / event stream</b><small>LOCAL</small></div>
            <div className="terminal-body">
              <div><span className="terminal-time">16:04:21</span><span className="terminal-allow">ALLOW</span><code>read_document <i>PUBLIC</i></code><Check size={13} /></div>
              <div><span className="terminal-time">16:04:22</span><span className="terminal-warn">WARN</span><code>deliver_to_sink <i>CONFIDENTIAL</i></code><Check size={13} /></div>
              <div className="terminal-block-row"><span className="terminal-time">16:04:23</span><span className="terminal-block">BLOCK</span><code>external delivery <i>SENSITIVE-EXTERNAL</i></code><LockKeyhole size={13} /></div>
              <div className="terminal-receipt"><span>DOWNSTREAM EXECUTIONS</span><strong>02</strong><span className="terminal-receipt-note">BLOCKED CALL NOT FORWARDED</span></div>
            </div>
            <div className="terminal-bottom"><span><i /> DECISION RECORDED</span><span>TRACE trc_…7e42</span></div>
          </div>
        </Reveal>
      </section>

      <footer className="landing-footer">
        <button className="landing-brand footer-brand" onClick={onOpenConsole} aria-label="Open MCP Sentinel console">
          <span className="landing-brand-mark"><SentinelMark /></span><span><strong>Sentinel</strong></span>
        </button>
        <span>Local-first MCP security demo · Phase 8 regression freeze</span>
        <button className="footer-console-link" onClick={onOpenConsole}>Enter console <ArrowUpRight size={13} /></button>
      </footer>
    </main>
  )
}
