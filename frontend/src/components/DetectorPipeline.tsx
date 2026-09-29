import { motion } from 'motion/react'
import { BrainCircuit, Fingerprint, Layers3, ScanSearch, ShieldCheck } from 'lucide-react'
import type { DetectorTrace } from '../types'
import { pretty } from '../lib/format'

const order = ['heuristic', 'semantic', 'trust_boundary', 'multiturn', 'llm_judge']
const icons = {
  heuristic: ScanSearch,
  semantic: Fingerprint,
  trust_boundary: ShieldCheck,
  multiturn: Layers3,
  llm_judge: BrainCircuit,
}

function statusClass(status: string) {
  if (['signal', 'untrusted', 'error'].includes(status)) return 'pipeline-danger'
  if (['clean', 'trusted'].includes(status)) return 'pipeline-clean'
  return 'pipeline-idle'
}

export function DetectorPipeline({ traces }: { traces: DetectorTrace[] }) {
  const mapped = order.map((layer) => traces.find((t) => t.layer === layer)).filter(Boolean) as DetectorTrace[]
  return (
    <div className="grid gap-2 md:grid-cols-5">
      {mapped.map((trace, index) => {
        const Icon = icons[trace.layer as keyof typeof icons] ?? ShieldCheck
        return (
          <motion.div
            key={`${trace.layer}-${trace.status}`}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.11, duration: 0.35 }}
            className={`pipeline-node ${statusClass(trace.status)}`}
          >
            <div className="flex items-center justify-between">
              <Icon className="h-4 w-4" />
              <span className="text-[10px] uppercase tracking-[0.14em] opacity-60">{trace.status}</span>
            </div>
            <div className="mt-4 text-xs font-semibold text-zinc-100">{pretty(trace.layer)}</div>
            <div className="mt-1 text-[11px] text-zinc-500">
              {trace.score > 0 ? `signal ${Math.round(trace.score * 100)}%` : trace.attack_types?.length ? trace.attack_types.join(', ') : 'no material signal'}
            </div>
          </motion.div>
        )
      })}
    </div>
  )
}
