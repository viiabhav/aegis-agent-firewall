import { motion } from 'motion/react'
import { Binary, Bot, BrainCircuit, FileSearch, Fingerprint, Layers3, Network, Scissors, ShieldCheck, type LucideIcon } from 'lucide-react'
import type { Health } from '../types'

const layers: Array<[string, string, LucideIcon]> = [
  ['Ingestion + normalization', 'PDF, DOCX, email, HTML, code, OCR and common obfuscation decoding.', FileSearch],
  ['Heuristic detector', 'Fast rules for known injection, exfiltration, role and tool-abuse patterns.', Binary],
  ['Semantic detector', 'Local MiniLM similarity against a curated multi-category attack corpus.', Fingerprint],
  ['Trust boundary', 'External content is explicitly untrusted before it can influence agent behavior.', ShieldCheck],
  ['Multi-turn state', 'Bounded conversation memory catches staged and split jailbreak sequences.', Layers3],
  ['LLM security judge', 'Optional structured judge for nuanced escalated cases; never the sole defense.', BrainCircuit],
  ['Decision + sanitization', 'Risk fusion returns ALLOW, SANITIZE, REVIEW or BLOCK with evidence.', Scissors],
  ['Adaptive threat testing', 'Generates, probes, reports gaps and falls back to deterministic replay.', Bot],
]

const flow = ['INGEST', 'NORMALIZE', 'DETECT', 'CORRELATE', 'JUDGE', 'DECIDE', 'SANITIZE']

export function ArchitecturePage({ health }: { health: Health | null }) {
  return (
    <div className="mx-auto max-w-[1300px] px-5 py-7 md:px-8">
      <div className="eyebrow">SYSTEM DESIGN</div>
      <h1 className="mt-2 text-2xl font-semibold tracking-tight text-white md:text-3xl">How AEGIS makes each decision.</h1>
      <p className="mt-2 max-w-3xl text-sm leading-6 text-zinc-400">AEGIS combines multiple independent checks instead of relying on one classifier. Each layer contributes evidence, and the final policy stays conservative when optional providers are unavailable.</p>

      <div className="architecture-flow mt-7">
        <div className="flex items-center justify-between gap-3"><div><div className="panel-title">Runtime signal path</div><div className="mt-1 text-xs text-zinc-400">Animated topology is illustrative; live detector evidence is shown on the Firewall page.</div></div><span className={`mini-badge ${health?.llm_configured ? 'text-emerald-200' : 'text-amber-200'}`}>LLM {health?.llm_configured ? 'ready' : 'optional'}</span></div>
        <div className="flow-track mt-7" aria-hidden="true"><div className="flow-line" />{flow.map((stage, index) => <div key={stage} className="flow-stage"><div className="flow-node">{index + 1}</div><div className="mt-2 text-[9px] font-semibold tracking-[.12em] text-zinc-500">{stage}</div></div>)}<motion.div className="flow-packet" animate={{ left: ['1%', '96%', '1%'] }} transition={{ duration: 7, repeat: Infinity, ease: 'easeInOut' }} /></div>
      </div>

      <div className="panel mt-5 overflow-hidden p-0">
        <div className="border-b border-white/8 px-6 py-5"><div className="flex items-center gap-2 text-sm font-semibold text-zinc-200"><Network className="h-4 w-4 text-cyan-300" />Runtime security layers</div></div>
        <div className="grid gap-px bg-white/5 md:grid-cols-2">{layers.map(([title, desc, Icon], index) => <motion.div key={title} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * .05 }} className="architecture-layer bg-[#0d1016] p-6"><div className="flex items-start gap-4"><div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-white/8 bg-white/[0.03]"><Icon className="h-4 w-4 text-cyan-300" /></div><div><div className="text-sm font-semibold text-zinc-200">{title}</div><p className="mt-2 text-xs leading-6 text-zinc-400">{desc}</p></div></div></motion.div>)}</div>
      </div>

      <div className="mt-5 grid gap-5 md:grid-cols-3">
        <div className="panel"><div className="eyebrow">DECLARED SCOPE</div><div className="mt-3 text-xl font-semibold text-white">F3 · D2</div><p className="mt-2 text-xs leading-6 text-zinc-400">Nine attack families implemented; structured/textual reliability is the core claim. OCR/images are bonus input paths, not a D3 reliability claim.</p></div>
        <div className="panel"><div className="eyebrow">FAIL-SAFE</div><div className="mt-3 text-xl font-semibold text-white">LLM ≠ authority</div><p className="mt-2 text-xs leading-6 text-zinc-400">Provider failure never defaults to allow. Strong deterministic evidence can still block/sanitize; ambiguous cases route to review.</p></div>
        <div className="panel"><div className="eyebrow">AGENTIC DIFFERENTIATOR</div><div className="mt-3 text-xl font-semibold text-white">Adaptive red team</div><p className="mt-2 text-xs leading-6 text-zinc-400">Generate → test → identify gaps → focus the next round. Replay mode keeps validation available when API quota is limited.</p></div>
      </div>
    </div>
  )
}
