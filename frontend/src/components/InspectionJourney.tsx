import { useEffect, useMemo, useState } from 'react'
import { motion } from 'motion/react'
import { Binary, BrainCircuit, CheckCircle2, FileSearch, Fingerprint, Layers3, Scissors, ShieldCheck } from 'lucide-react'

const stages = [
  { label: 'Normalize', Icon: FileSearch },
  { label: 'Heuristic', Icon: Binary },
  { label: 'Semantic', Icon: Fingerprint },
  { label: 'Trust', Icon: ShieldCheck },
  { label: 'Multi-turn', Icon: Layers3 },
  { label: 'LLM judge', Icon: BrainCircuit },
  { label: 'Decision', Icon: Scissors },
]

export function InspectionJourney({ running, llmEnabled }: { running: boolean; llmEnabled: boolean }) {
  const [active, setActive] = useState(0)
  useEffect(() => {
    if (!running) { setActive(0); return }
    setActive(0)
    const timer = window.setInterval(() => setActive((value) => Math.min(stages.length - 1, value + 1)), 440)
    return () => window.clearInterval(timer)
  }, [running])

  const visibleStages = useMemo(() => stages.map((stage) => stage.label === 'LLM judge' && !llmEnabled ? { ...stage, label: 'LLM optional' } : stage), [llmEnabled])

  return (
    <div className="journey-shell" aria-label={running ? 'AEGIS inspection in progress' : 'AEGIS defense path ready'}>
      <div className="flex items-center justify-between gap-4">
        <div>
          <div className="eyebrow">DEFENSE PATH</div>
          <div className="mt-2 text-sm font-semibold text-white">{running ? 'Inspection moving through AEGIS' : 'Seven-stage security path armed'}</div>
          <p className="mt-1 text-xs leading-5 text-zinc-400">{running ? 'The animation shows orchestration progress; detector statuses appear only after the real response returns.' : 'Run an inspection to replace this readiness view with actual detector evidence.'}</p>
        </div>
        <div className={`journey-state ${running ? 'journey-state-live' : ''}`}>
          {running ? <><span className="journey-live-dot" />LIVE</> : <><CheckCircle2 className="h-3.5 w-3.5" />READY</>}
        </div>
      </div>

      <div className="journey-track mt-7">
        <div className="journey-line" aria-hidden="true" />
        {visibleStages.map(({ label, Icon }, index) => {
          const reached = running && index <= active
          const current = running && index === active
          return (
            <div key={label} className="journey-step">
              <motion.div
                animate={current ? { scale: [1, 1.1, 1] } : { scale: 1 }}
                transition={current ? { repeat: Infinity, duration: 1.25 } : {}}
                className={`journey-node ${reached ? 'journey-node-reached' : ''} ${current ? 'journey-node-current' : ''}`}
              >
                <Icon className="h-4 w-4" />
              </motion.div>
              <div className={`journey-label ${reached ? 'text-zinc-200' : ''}`}>{label}</div>
            </div>
          )
        })}
        {running && <motion.div className="journey-packet" initial={{ left: '1%' }} animate={{ left: `${Math.min(96, (active / (stages.length - 1)) * 96 + 1)}%` }} transition={{ type: 'spring', stiffness: 120, damping: 20 }} aria-hidden="true" />}
      </div>
    </div>
  )
}
