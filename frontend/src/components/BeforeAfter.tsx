import { ArrowRight, CheckCircle2, Scissors } from 'lucide-react'
import type { Redaction } from '../types'

function OriginalWithRedactions({ text, redactions }: { text: string; redactions: Redaction[] }) {
  if (!redactions.length) return <>{text}</>
  const ordered = [...redactions].sort((a, b) => a.start - b.start)
  const nodes = []
  let cursor = 0
  ordered.forEach((redaction, index) => {
    const start = Math.max(cursor, redaction.start)
    const end = Math.max(start, redaction.end)
    if (start > cursor) nodes.push(<span key={`plain-${index}`}>{text.slice(cursor, start)}</span>)
    nodes.push(<mark key={`redact-${index}`} className="redaction-source" title={`Removed by ${redaction.layers.join(', ') || 'AEGIS'}`}>{text.slice(start, end) || redaction.original}</mark>)
    cursor = end
  })
  if (cursor < text.length) nodes.push(<span key="tail">{text.slice(cursor)}</span>)
  return <>{nodes}</>
}

export function BeforeAfter({ before, after, changed, redactions = [] }: { before: string; after: string; changed: boolean; redactions?: Redaction[] }) {
  return (
    <div className="panel">
      <div className="flex items-center justify-between gap-3">
        <div><div className="panel-title">Safe downstream content</div><div className="mt-1 text-xs text-zinc-400">AEGIS preserves useful context whenever a malicious span can be removed safely.</div></div>
        <div className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[10px] font-semibold ${changed ? 'bg-cyan-400/10 text-cyan-300' : 'bg-emerald-400/10 text-emerald-300'}`}>
          {changed ? <Scissors className="h-3 w-3" /> : <CheckCircle2 className="h-3 w-3" />}
          {changed ? `${redactions.length || 1} REDACTION${redactions.length === 1 ? '' : 'S'}` : 'UNCHANGED'}
        </div>
      </div>
      <div className="mt-4 grid gap-3 lg:grid-cols-[1fr_auto_1fr] lg:items-stretch">
        <div className="code-box">
          <div className="code-label">Original</div>
          <div className="mt-2 whitespace-pre-wrap"><OriginalWithRedactions text={before} redactions={redactions} /></div>
        </div>
        <div className="hidden items-center lg:flex"><ArrowRight className="h-4 w-4 text-zinc-600" /></div>
        <div className="code-box border-cyan-300/15 bg-cyan-400/[0.03]">
          <div className="code-label text-cyan-300/80">Forwarded</div>
          <div className="mt-2 whitespace-pre-wrap text-zinc-300">{after || 'Content blocked — nothing forwarded downstream.'}</div>
        </div>
      </div>
      {redactions.length > 0 && <div className="mt-3 flex flex-wrap gap-2">{redactions.slice(0, 4).map((item, index) => <span key={index} className="mini-badge">Removed: {item.original.slice(0, 44)}{item.original.length > 44 ? '…' : ''}</span>)}</div>}
    </div>
  )
}
