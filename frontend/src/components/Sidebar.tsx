import { Activity, FlaskConical, Network, Radar, Shield } from 'lucide-react'
import { Brand } from './Brand'

export type PageKey = 'firewall' | 'redteam' | 'posture' | 'architecture'

const nav = [
  { id: 'firewall' as const, label: 'Firewall', icon: Shield },
  { id: 'redteam' as const, label: 'Threat Lab', icon: FlaskConical },
  { id: 'posture' as const, label: 'Security Insights', icon: Radar },
  { id: 'architecture' as const, label: 'System Design', icon: Network },
]

export function Sidebar({ page, onChange }: { page: PageKey; onChange: (page: PageKey) => void }) {
  return (
    <aside className="hidden min-h-screen w-[248px] shrink-0 border-r border-white/8 bg-[#090b10]/94 px-4 py-5 backdrop-blur-xl lg:flex lg:flex-col">
      <Brand />
      <div className="mt-9 text-[10px] font-semibold uppercase tracking-[0.22em] text-zinc-400">Workspace</div>
      <nav aria-label="Primary workspace" className="mt-3 space-y-1.5">
        {nav.map((item) => {
          const Icon = item.icon
          const active = page === item.id
          return (
            <button
              type="button"
              key={item.id}
              onClick={() => onChange(item.id)}
              aria-current={active ? 'page' : undefined}
              className={`group flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition ${
                active
                  ? 'border border-white/10 bg-white/[0.065] text-white shadow-[inset_0_1px_rgba(255,255,255,0.04)]'
                  : 'border border-transparent text-zinc-400 hover:bg-white/[0.045] hover:text-zinc-100'
              }`}
            >
              <Icon className={`h-4 w-4 ${active ? 'text-cyan-200' : 'text-zinc-500 group-hover:text-zinc-300'}`} aria-hidden="true" />
              {item.label}
              {active && <span aria-hidden="true" className="ml-auto h-1.5 w-1.5 rounded-full bg-cyan-300 shadow-[0_0_10px_rgba(103,232,249,.8)]" />}
            </button>
          )
        })}
      </nav>
      <div className="mt-auto space-y-3">
        <div className="rounded-2xl border border-white/9 bg-white/[0.028] p-4">
          <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-300/75">Hackathon build</div>
          <div className="mt-2 text-xs font-semibold text-zinc-200">Vaibhav Patil</div>
          <div className="mt-1 text-[11px] text-zinc-400">Team Beyond Tokens</div>
          <div className="mt-3 border-t border-white/7 pt-3 text-[10px] leading-4 text-zinc-500">ET AI Hackathon 2026 · Agentic Edition<br />Presented by Accenture</div>
        </div>
        <div className="rounded-2xl border border-white/9 bg-white/[0.035] p-4">
        <div className="flex items-center gap-2 text-xs text-zinc-300">
          <Activity className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
          Defense-in-depth active
        </div>
        <p className="mt-2 text-[11px] leading-5 text-zinc-400">Heuristic · Semantic · Trust · Multi-turn · LLM</p>
        </div>
      </div>
    </aside>
  )
}
