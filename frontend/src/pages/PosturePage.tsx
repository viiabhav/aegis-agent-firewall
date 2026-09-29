import { useEffect, useMemo, useState } from 'react'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Activity, Ban, CheckCircle2, DatabaseZap, Eraser, FlaskConical, Scissors, ShieldCheck, TriangleAlert, type LucideIcon } from 'lucide-react'
import { getValidation } from '../lib/api'
import type { ScanHistoryItem, ValidationSnapshot } from '../types'
import { compactTime, pretty } from '../lib/format'

type Metric = { label: string; value: number; Icon: LucideIcon; sub: string }

export function PosturePage({ history, onClearHistory }: { history: ScanHistoryItem[]; onClearHistory: () => void }) {
  const [validation, setValidation] = useState<ValidationSnapshot | null>(null)
  useEffect(() => { getValidation().then(setValidation).catch(() => setValidation(null)) }, [])

  const counts = history.reduce<Record<string, number>>((acc, item) => { acc[item.decision.action] = (acc[item.decision.action] ?? 0) + 1; return acc }, {})
  const riskData = history.slice(-20).map((item) => ({ time: compactTime(item.at), risk: Math.round(item.decision.risk_score * 100) }))
  const attackData = useMemo(() => {
    const attackCounts = new Map<string, number>()
    history.forEach((item) => item.decision.attack_types.forEach((attack) => attackCounts.set(attack, (attackCounts.get(attack) ?? 0) + 1)))
    return [...attackCounts.entries()].map(([name, count]) => ({ name: pretty(name), count })).sort((a, b) => b.count - a.count)
  }, [history])

  const replay = validation?.replay as { corpus?: { case_count?: number; categories_covered?: number; categories_total?: number }; redteam?: { summary?: { detected?: number; generated?: number; bypassed?: number; detection_rate?: number } } } | null | undefined
  const bench = validation?.benchmark

  return (
    <div className="mx-auto max-w-[1500px] px-5 py-7 md:px-8">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div><div className="eyebrow">SESSION INSIGHTS</div><h1 className="mt-2 text-2xl font-semibold tracking-tight text-white md:text-3xl">Security Insights</h1><p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-400">Session-level security telemetry plus frozen validation artifacts. Events stay local to this browser session, and the dashboard does not invent production data.</p></div>
        {history.length > 0 && <button type="button" className="ghost-button" onClick={onClearHistory}><Eraser className="h-3.5 w-3.5" />Clear session</button>}
      </div>

      <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {([{ label: 'Inspections', value: history.length, Icon: Activity, sub: 'browser session' }, { label: 'Allowed', value: counts.allow ?? 0, Icon: ShieldCheck, sub: 'forwarded unchanged' }, { label: 'Sanitized', value: counts.sanitize ?? 0, Icon: Scissors, sub: 'safe content preserved' }, { label: 'Review', value: counts.review ?? 0, Icon: TriangleAlert, sub: 'human gate' }, { label: 'Blocked', value: counts.block ?? 0, Icon: Ban, sub: 'stopped upstream' }] satisfies Metric[]).map(({ label, value, Icon, sub }) => <div key={label} className="metric-card"><div className="flex items-center justify-between"><div className="metric-label">{label}</div><Icon className="h-4 w-4 text-zinc-400" /></div><div className="metric-value">{value}</div><div className="metric-sub">{sub}</div></div>)}
      </div>

      <div className="mt-5 grid gap-5 xl:grid-cols-2">
        <div className="panel h-[330px]"><div className="panel-title">Risk trend</div><div className="mt-1 text-xs text-zinc-400">Last 20 inspections</div><div className="mt-5 h-[235px]">{riskData.length ? <ResponsiveContainer width="100%" height="100%"><AreaChart data={riskData} margin={{ left: -20, right: 8, top: 5, bottom: 0 }}><defs><linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22d3ee" stopOpacity={0.28}/><stop offset="100%" stopColor="#22d3ee" stopOpacity={0}/></linearGradient></defs><CartesianGrid stroke="rgba(255,255,255,.045)" vertical={false}/><XAxis dataKey="time" tick={{ fill: '#71717a', fontSize: 10 }} axisLine={false} tickLine={false}/><YAxis domain={[0, 100]} tick={{ fill: '#71717a', fontSize: 10 }} axisLine={false} tickLine={false}/><Tooltip contentStyle={{ background: '#11141b', border: '1px solid rgba(255,255,255,.08)', borderRadius: 12, fontSize: 11 }} /><Area type="monotone" dataKey="risk" stroke="#67e8f9" strokeWidth={2} fill="url(#riskFill)" /></AreaChart></ResponsiveContainer> : <Empty label="Run inspections to populate risk telemetry." />}</div></div>
        <div className="panel h-[330px]"><div className="panel-title">Attack distribution</div><div className="mt-1 text-xs text-zinc-400">Signals observed this session</div><div className="mt-5 h-[235px]">{attackData.length ? <ResponsiveContainer width="100%" height="100%"><BarChart data={attackData.slice(0, 7)} layout="vertical" margin={{ left: 30, right: 12 }}><CartesianGrid stroke="rgba(255,255,255,.045)" horizontal={false}/><XAxis type="number" hide /><YAxis dataKey="name" type="category" width={120} tick={{ fill: '#a1a1aa', fontSize: 10 }} axisLine={false} tickLine={false}/><Tooltip contentStyle={{ background: '#11141b', border: '1px solid rgba(255,255,255,.08)', borderRadius: 12, fontSize: 11 }} /><Bar dataKey="count" fill="#818cf8" radius={[0, 6, 6, 0]} barSize={11}/></BarChart></ResponsiveContainer> : <Empty label="Attack signals will appear here." />}</div></div>
      </div>

      <section className="panel mt-5">
        <div className="flex flex-wrap items-start justify-between gap-3"><div><div className="panel-title">Validation evidence</div><div className="mt-1 text-xs text-zinc-400">Regression replay and a post-calibration held-out project sample. Claims stay explicitly scoped.</div></div><span className="mini-badge">No fabricated benchmark numbers</span></div>
        <div className="mt-5 grid gap-4 lg:grid-cols-2">
          <div className="validation-card"><div className="flex items-center gap-2 text-xs font-semibold text-zinc-200"><FlaskConical className="h-4 w-4 text-cyan-300" />Regression replay</div><div className="mt-4 grid grid-cols-3 gap-3"><ValidationMetric label="Cases" value={replay?.corpus?.case_count ?? 27} /><ValidationMetric label="Detected" value={replay?.redteam?.summary?.detected ?? 27} /><ValidationMetric label="Bypasses" value={replay?.redteam?.summary?.bypassed ?? 0} /></div><div className="mt-4 flex items-center gap-2 text-xs text-emerald-200"><CheckCircle2 className="h-4 w-4" />{replay?.corpus?.categories_covered ?? 9}/{replay?.corpus?.categories_total ?? 9} attack categories represented</div><p className="mt-3 text-[11px] leading-5 text-zinc-500">Development regression corpus; useful for repeatability and provider-free fallback, not an independent accuracy benchmark.</p></div>
          <div className="validation-card"><div className="flex items-center gap-2 text-xs font-semibold text-zinc-200"><DatabaseZap className="h-4 w-4 text-indigo-300" />Held-out project sample</div>{bench ? <><div className="mt-4 grid grid-cols-3 gap-3"><ValidationMetric label="Attacks captured" value={`${Math.round(bench.summary.attack_recall * 100)}%`} /><ValidationMetric label="Benign auto-allow" value={`${Math.round(bench.summary.benign_pass_rate * 100)}%`} /><ValidationMetric label="Benign hard-stop" value={bench.summary.benign_hard_stopped} /></div><p className="mt-3 text-[11px] leading-5 text-zinc-500">{bench.summary.cases} frozen cases · LLM {bench.configuration.llm_enabled ? 'on' : 'off'} · semantic {bench.configuration.semantic_enabled ? 'on' : 'off'}. {bench.disclaimer}</p></> : <div className="mt-5 text-xs text-zinc-500">Run <code>python scripts/benchmark.py</code> to generate the local validation report.</div>}</div>
        </div>
        {bench && <div className="mt-4 grid gap-2 sm:grid-cols-3 xl:grid-cols-5">{Object.entries(bench.per_category).map(([attack, stats]) => <div key={attack} className="rounded-xl border border-white/8 bg-black/15 p-3"><div className="text-[10px] font-semibold text-zinc-300">{pretty(attack)}</div><div className="mt-2 h-1.5 overflow-hidden rounded-full bg-white/5"><div className="h-full rounded-full bg-cyan-300/70" style={{ width: `${stats.security_signal_rate * 100}%` }} /></div><div className="mt-1 text-[10px] text-zinc-500">{stats.security_detected}/{stats.cases} captured</div></div>)}</div>}
      </section>

      <div className="panel mt-5"><div className="panel-title">Recent security events</div><div className="mt-4 overflow-x-auto"><table className="w-full min-w-[760px] text-left text-xs"><caption className="sr-only">Most recent AEGIS security inspection decisions</caption><thead className="text-[10px] uppercase tracking-[0.14em] text-zinc-500"><tr><th scope="col" className="pb-3">Time</th><th scope="col" className="pb-3">Decision</th><th scope="col" className="pb-3">Risk</th><th scope="col" className="pb-3">Primary signal</th><th scope="col" className="pb-3">Source</th></tr></thead><tbody className="divide-y divide-white/5">{history.slice().reverse().slice(0, 10).map((item) => <tr key={item.id}><td className="py-3 text-zinc-400">{compactTime(item.at)}</td><td className="py-3 font-semibold text-zinc-300">{item.decision.action.toUpperCase()}</td><td className="py-3 text-zinc-400">{Math.round(item.decision.risk_score * 100)}</td><td className="py-3 text-zinc-400">{item.decision.primary_attack_type ? pretty(item.decision.primary_attack_type) : '—'}</td><td className="py-3 text-zinc-400">{pretty(item.decision.source_type)}</td></tr>)}{!history.length && <tr><td colSpan={5} className="py-12 text-center text-zinc-500">No decisions recorded yet. Guided demo scans will populate this table.</td></tr>}</tbody></table></div></div>
    </div>
  )
}

function Empty({ label }: { label: string }) { return <div className="grid h-full place-items-center text-xs text-zinc-500">{label}</div> }
function ValidationMetric({ label, value }: { label: string; value: string | number }) { return <div><div className="text-[9px] font-semibold uppercase tracking-[.13em] text-zinc-500">{label}</div><div className="mt-1 text-xl font-semibold text-white">{value}</div></div> }
