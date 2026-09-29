import { BrainCircuit, CloudOff, Cpu, Wifi } from 'lucide-react'
import type { Health } from '../types'

function StatusDot({ ok }: { ok: boolean }) {
  return <span aria-hidden="true" className={`h-1.5 w-1.5 rounded-full ${ok ? 'bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,.6)]' : 'bg-amber-400'}`} />
}

export function Topbar({ health }: { health: Health | null }) {
  const apiOk = health?.status === 'ok'
  return (
    <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-white/8 bg-[#0a0c11]/92 px-5 backdrop-blur-xl md:px-8">
      <div>
        <div className="text-xs font-medium text-zinc-400">Adaptive AI Security Gateway</div>
        <div className="mt-0.5 text-sm font-semibold text-zinc-100">Prompt Injection Firewall</div>
      </div>
      <div className="flex items-center gap-2" aria-label="System status">
        <div className="status-pill hidden sm:flex" role="status">
          <StatusDot ok={apiOk} />
          <Wifi className="h-3.5 w-3.5" aria-hidden="true" />
          API {apiOk ? 'online' : 'checking'}
        </div>
        <div className="status-pill hidden sm:flex">
          <Cpu className="h-3.5 w-3.5" aria-hidden="true" />
          Local semantic
        </div>
        <div className={`status-pill ${health?.llm_configured ? 'status-ready' : 'status-warning'}`} title={health?.llm_configured ? `${health.llm_provider} · ${health.llm_model}` : 'LLM Judge is not configured yet'}>
          {health?.llm_configured ? <BrainCircuit className="h-3.5 w-3.5" aria-hidden="true" /> : <CloudOff className="h-3.5 w-3.5" aria-hidden="true" />}
          LLM {health?.llm_configured ? 'ready' : 'setup'}
        </div>
      </div>
    </header>
  )
}
