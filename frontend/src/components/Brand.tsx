import { ShieldCheck } from 'lucide-react'

export function Brand() {
  return (
    <div className="flex items-center gap-3">
      <div className="grid h-10 w-10 place-items-center rounded-xl border border-cyan-400/25 bg-cyan-400/10 shadow-[0_0_40px_rgba(34,211,238,0.08)]">
        <ShieldCheck className="h-5 w-5 text-cyan-300" />
      </div>
      <div>
        <div className="text-[11px] font-semibold tracking-[0.24em] text-cyan-300/80">AEGIS</div>
        <div className="text-sm font-semibold text-white">Console</div>
      </div>
    </div>
  )
}
