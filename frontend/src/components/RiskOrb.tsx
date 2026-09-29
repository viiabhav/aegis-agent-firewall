import { motion } from 'motion/react'
import type { FirewallAction } from '../types'

const actionTheme: Record<FirewallAction, { label: string; accent: string; glow: string }> = {
  allow: { label: 'ALLOW', accent: '#34d399', glow: 'rgba(52,211,153,.22)' },
  sanitize: { label: 'SANITIZE', accent: '#22d3ee', glow: 'rgba(34,211,238,.22)' },
  review: { label: 'REVIEW', accent: '#fbbf24', glow: 'rgba(251,191,36,.22)' },
  block: { label: 'BLOCK', accent: '#fb7185', glow: 'rgba(251,113,133,.22)' },
}

export function RiskOrb({ action, risk }: { action: FirewallAction; risk: number }) {
  const theme = actionTheme[action]
  const degrees = Math.max(2, Math.round(risk * 360))
  return (
    <div className="relative grid place-items-center" role="status" aria-label={`${theme.label} decision with risk score ${Math.round(risk * 100)} out of 100`}>
      <motion.div
        initial={{ scale: 0.88, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ type: 'spring', stiffness: 140, damping: 18 }}
        className="relative grid h-44 w-44 place-items-center rounded-full"
        style={{
          background: `conic-gradient(${theme.accent} ${degrees}deg, rgba(255,255,255,.055) ${degrees}deg)`,
          boxShadow: `0 0 70px ${theme.glow}`,
        }}
      >
        <div className="absolute inset-[7px] rounded-full bg-[#0b0e14]" />
        <div className="relative z-10 text-center">
          <div className="text-[10px] font-semibold tracking-[0.24em] text-zinc-500">RISK SCORE</div>
          <motion.div
            key={risk}
            initial={{ y: 8, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            className="mt-1 text-4xl font-semibold tracking-tight text-white"
          >
            {Math.round(risk * 100)}
          </motion.div>
          <div className="mt-2 text-xs font-bold tracking-[0.22em]" style={{ color: theme.accent }}>
            {theme.label}
          </div>
        </div>
      </motion.div>
    </div>
  )
}
