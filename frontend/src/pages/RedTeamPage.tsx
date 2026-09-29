import { useMemo, useState } from 'react'
import { motion } from 'motion/react'
import { AlertTriangle, Bot, CheckCircle2, Crosshair, LoaderCircle, Play, RadioTower, Shield, Swords, Zap } from 'lucide-react'
import { runLiveRedTeam, runReplay } from '../lib/api'
import { pct, pretty } from '../lib/format'
import type { Health, LiveRedTeamResponse, ReplayResponse } from '../types'

const liveAttackTypes = ['instruction_override', 'tool_abuse', 'multi_step_jailbreak', 'indirect_prompt_injection']

export function RedTeamPage({ health }: { health: Health | null }) {
  const [semantic, setSemantic] = useState(true)
  const [mode, setMode] = useState<'replay' | 'live'>('replay')
  const [result, setResult] = useState<ReplayResponse | null>(null)
  const [liveResult, setLiveResult] = useState<LiveRedTeamResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function replay() {
    setLoading(true); setError(''); setLiveResult(null)
    try { setResult(await runReplay(semantic)) }
    catch (err) { setError(err instanceof Error ? err.message : String(err)) }
    finally { setLoading(false) }
  }

  async function live() {
    setLoading(true); setError(''); setResult(null)
    try { setLiveResult(await runLiveRedTeam(liveAttackTypes)) }
    catch (err) { setError(err instanceof Error ? err.message : String(err)) }
    finally { setLoading(false) }
  }

  const replayTimeline = useMemo(() => result ? Object.entries(result.coverage).map(([attack, stats]) => ({ kind: 'tested', message: `${pretty(attack)} · ${stats.detected ?? 0}/${stats.generated ?? 0} security-detected` })) : [], [result])
  const timeline = liveResult?.events ?? replayTimeline

  const liveSummary = liveResult?.report.summary

  return (
    <div className="mx-auto max-w-[1500px] px-5 py-7 md:px-8">
      <div className="flex flex-col justify-between gap-4 xl:flex-row xl:items-end">
        <div><div className="eyebrow">ADVERSARIAL VALIDATION</div><h1 className="mt-2 text-2xl font-semibold tracking-tight text-white md:text-3xl">Threat Lab</h1><p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-400">Test how AEGIS responds to prompt-injection attempts through live simulation and repeatable replay. Live tests can use Groq when available; replay keeps validation available without external generation.</p></div>
        <div className="arena-mode-switch" role="tablist" aria-label="Red-team mode">
          <button type="button" role="tab" aria-selected={mode === 'replay'} className={mode === 'replay' ? 'arena-mode-active' : ''} onClick={() => setMode('replay')}>Replay mode</button>
          <button type="button" role="tab" aria-selected={mode === 'live'} className={mode === 'live' ? 'arena-mode-active' : ''} onClick={() => setMode('live')}>Live simulation</button>
        </div>
      </div>

      <div className="mt-6 grid gap-5 xl:grid-cols-[1fr_360px_1fr]">
        <div className="arena-side arena-attacker"><div className="flex items-center gap-2"><Swords className="h-4 w-4 text-rose-300" /><span className="text-xs font-semibold text-zinc-200">PROBE GENERATOR</span></div><div className="mt-8 grid place-items-center text-center"><div className="arena-orb border-rose-300/15 bg-rose-400/[0.04]"><Bot className="h-7 w-7 text-rose-300" /></div><div className="mt-4 text-sm font-semibold text-zinc-200">{mode === 'live' ? 'LLM probe generator' : 'Threat scenario corpus'}</div><div className="mt-2 text-xs leading-5 text-zinc-400">{mode === 'live' ? 'Novel variants · four representative categories · quota-aware' : '27 persisted attacks · 9 categories · multi-source · multi-turn'}</div></div></div>

        <div className="panel flex min-h-[310px] flex-col items-center justify-center text-center">
          <motion.div animate={loading ? { rotate: 360 } : { rotate: 0 }} transition={loading ? { repeat: Infinity, duration: 2, ease: 'linear' } : {}} className="relative grid h-24 w-24 place-items-center rounded-full border border-cyan-300/15 bg-cyan-400/[0.035] shadow-[0_0_70px_rgba(34,211,238,.08)]"><Shield className="h-8 w-8 text-cyan-300" /><span className="absolute -inset-2 rounded-full border border-dashed border-white/8" /></motion.div>
          <div className="mt-5 text-sm font-semibold text-white">AEGIS evaluator</div>
          <div className="mt-2 text-xs text-zinc-400">{mode === 'live' ? 'generate → test → gap → adapt' : 'provider generation not required'}</div>
          {mode === 'replay' ? <><label className="toggle-pill mt-5"><input aria-label="Enable semantic layer for replay" type="checkbox" checked={semantic} onChange={(e) => setSemantic(e.target.checked)} /><span>Semantic layer</span></label><button type="button" onClick={replay} disabled={loading} className="scan-button mt-4 w-full" aria-busy={loading}>{loading ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4 fill-current" />}{loading ? 'Running campaign…' : 'Replay 27-case campaign'}</button></> : <><div className={`mt-5 inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-[10px] font-semibold ${health?.llm_configured ? 'border-emerald-300/15 bg-emerald-400/[0.04] text-emerald-200' : 'border-amber-300/15 bg-amber-400/[0.04] text-amber-200'}`}><RadioTower className="h-3.5 w-3.5" />{health?.llm_configured ? 'Groq configured' : 'Provider setup required'}</div><button type="button" onClick={live} disabled={loading || !health?.llm_configured} className="scan-button mt-4 w-full" aria-busy={loading}>{loading ? <LoaderCircle className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4 fill-current" />}{loading ? 'Agent probing…' : 'Run quick live campaign'}</button><div className="mt-2 text-[10px] leading-4 text-zinc-500">4 categories · 1 variant · 1 round. If quota is exhausted, use Replay mode.</div></>}
        </div>

        <div className="arena-side arena-defender"><div className="flex items-center gap-2"><Shield className="h-4 w-4 text-cyan-300" /><span className="text-xs font-semibold text-zinc-200">AEGIS</span></div><div className="mt-8 grid place-items-center text-center"><div className="arena-orb border-cyan-300/15 bg-cyan-400/[0.04]"><Crosshair className="h-7 w-7 text-cyan-300" /></div><div className="mt-4 text-sm font-semibold text-zinc-200">Defense layers</div><div className="mt-2 text-xs leading-5 text-zinc-400">Heuristic · semantic · escalation · trust · multi-turn · LLM</div></div></div>
      </div>

      {error && <div role="alert" className="mt-5 rounded-xl border border-rose-400/25 bg-rose-400/10 p-4 text-xs text-rose-100">{error}<div className="mt-2 text-rose-100/70">Replay mode remains available even if the live provider is rate-limited.</div></div>}

      {(result || liveResult) && <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} className="mt-5 space-y-5">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          {result ? [
            ['Replayed', result.summary.replayed, 'cases'], ['Security detected', result.summary.detected, pct(result.summary.security_signal_rate)], ['Bypasses', result.summary.bypassed, 'regression corpus'], ['Errors', result.summary.errors, 'provider-free'], ['Categories', result.corpus.categories_covered, `of ${result.corpus.categories_total}`],
          ].map(([label, value, sub]) => <div className="metric-card" key={String(label)}><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-sub">{sub}</div></div>) : [
            ['Generated', liveSummary?.generated ?? 0, 'novel probes'], ['Detected', liveSummary?.detected ?? 0, liveSummary ? pct(liveSummary.detection_rate) : '—'], ['Bypasses', liveSummary?.bypassed ?? 0, 'sample only'], ['Errors', liveSummary?.evaluation_errors ?? 0, 'provider/runtime'], ['Gaps', (liveSummary?.detector_gaps ?? 0) + (liveSummary?.escalation_gaps ?? 0), 'human review'],
          ].map(([label, value, sub]) => <div className="metric-card" key={String(label)}><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-sub">{sub}</div></div>)}
        </div>

        <div className="grid gap-5 xl:grid-cols-[.9fr_1.1fr]">
          <div className="panel"><div className="flex items-center justify-between"><div><div className="panel-title">Validation event stream</div><div className="mt-1 text-xs text-zinc-400">{mode === 'live' ? 'Events returned by the live simulation' : 'Actual category outcomes from deterministic replay'}</div></div><div className="mini-badge">{timeline.length} events</div></div><div className="arena-timeline mt-5">{timeline.length ? timeline.slice(0, 18).map((event, index) => <motion.div key={`${event.kind}-${index}`} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: index * .035 }} className="arena-event"><span className={`arena-event-dot ${event.kind.includes('gap') || event.kind.includes('error') ? 'arena-event-warn' : event.kind.includes('complete') || event.kind === 'tested' ? 'arena-event-ok' : ''}`} /><div><div className="text-[10px] font-semibold uppercase tracking-[.14em] text-zinc-500">{pretty(event.kind)}</div><div className="mt-1 text-xs leading-5 text-zinc-300">{event.message}</div></div></motion.div>) : <div className="py-10 text-center text-xs text-zinc-500">Run a campaign to populate the event stream.</div>}</div></div>

          {result ? <div className="panel"><div className="flex flex-wrap items-start justify-between gap-3"><div><div className="panel-title">Coverage matrix</div><div className="mt-1 text-xs text-zinc-400">Regression replay · not an independent benchmark</div></div><div className="flex items-center gap-2 text-xs text-emerald-300"><CheckCircle2 className="h-4 w-4" />Fallback operational</div></div><div className="mt-5 grid gap-3 md:grid-cols-2">{Object.entries(result.coverage).map(([attack, stats], index) => { const generated = stats.generated ?? 0; const detected = stats.detected ?? 0; const rate = generated ? detected / generated : 0; return <motion.div key={attack} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * .04 }} className="rounded-xl border border-white/8 bg-black/15 p-4"><div className="flex items-center justify-between"><span className="text-xs font-semibold text-zinc-300">{pretty(attack)}</span><span className="text-[11px] text-zinc-400">{detected}/{generated}</span></div><div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/5"><motion.div initial={{ width: 0 }} animate={{ width: `${rate * 100}%` }} className="h-full rounded-full bg-cyan-300/70" /></div><div className="mt-2 flex justify-between text-[10px] text-zinc-400"><span>security signal</span><span>{Math.round(rate * 100)}%</span></div></motion.div>})}</div></div> : <div className="panel"><div className="panel-title">Live campaign scope</div><div className="mt-4 grid gap-3 sm:grid-cols-2">{liveAttackTypes.map((attack) => <div key={attack} className="rounded-xl border border-white/8 bg-black/15 p-4 text-xs font-semibold text-zinc-300">{pretty(attack)}</div>)}</div><div className="mt-4 rounded-xl border border-amber-300/12 bg-amber-400/[0.03] p-4 text-xs leading-6 text-amber-100/70">Live results are an observed adversarial sample, not a benchmark. The generator and evaluator depend on provider quota.</div></div>}
        </div>

        {result && <div className="rounded-xl border border-amber-400/12 bg-amber-400/[0.035] p-4 text-xs leading-6 text-amber-100/65"><AlertTriangle className="mr-2 inline h-4 w-4" />This replay corpus was generated/curated during development. It validates regression behavior and fallback availability; it is not presented as an independent accuracy benchmark.</div>}
      </motion.div>}
    </div>
  )
}
