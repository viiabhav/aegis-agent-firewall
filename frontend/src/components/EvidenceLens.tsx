import { useState } from 'react'
import type { EvidenceItem } from '../types'
import { pretty } from '../lib/format'

function highlightText(input: string, evidence: EvidenceItem[], selected: number | null) {
  const ranges: Array<{ start: number; end: number; indexes: number[] }> = []
  const lower = input.toLowerCase()
  evidence.forEach((item, index) => {
    const needle = item.evidence.trim()
    if (needle.length < 4) return
    const idx = lower.indexOf(needle.toLowerCase())
    if (idx >= 0) ranges.push({ start: idx, end: idx + needle.length, indexes: [index] })
  })
  if (!ranges.length) return [<span key="all">{input}</span>]
  ranges.sort((a, b) => a.start - b.start)
  const merged: typeof ranges = []
  for (const range of ranges) {
    const last = merged.at(-1)
    if (last && range.start <= last.end) {
      last.end = Math.max(last.end, range.end)
      last.indexes.push(...range.indexes)
    } else merged.push({ ...range, indexes: [...range.indexes] })
  }
  const out = []
  let cursor = 0
  merged.forEach((range, i) => {
    if (range.start > cursor) out.push(<span key={`t-${i}`}>{input.slice(cursor, range.start)}</span>)
    const isSelected = selected === null || range.indexes.includes(selected)
    out.push(<mark key={`m-${i}`} className={`evidence-mark ${isSelected ? 'evidence-mark-selected' : 'evidence-mark-muted'}`}>{input.slice(range.start, range.end)}</mark>)
    cursor = range.end
  })
  if (cursor < input.length) out.push(<span key="tail">{input.slice(cursor)}</span>)
  return out
}

export function EvidenceLens({ input, evidence }: { input: string; evidence: EvidenceItem[] }) {
  const [selected, setSelected] = useState<number | null>(null)
  return (
    <div className="panel">
      <div className="flex items-start justify-between gap-3">
        <div><div className="panel-title">Evidence lens</div><div className="mt-1 text-xs text-zinc-400">Select a signal to isolate the exact suspicious span.</div></div>
        {selected !== null && <button type="button" className="ghost-button" onClick={() => setSelected(null)}>Show all</button>}
      </div>
      <div className="mt-3 max-h-56 overflow-auto whitespace-pre-wrap rounded-xl border border-white/8 bg-black/25 p-4 font-mono text-xs leading-6 text-zinc-300">
        {highlightText(input, evidence, selected)}
      </div>
      {evidence.length > 0 ? (
        <div className="mt-3 grid gap-2 md:grid-cols-2">
          {evidence.slice(0, 6).map((item, index) => (
            <button type="button" onClick={() => setSelected(selected === index ? null : index)} key={`${item.layer}-${index}`} className={`evidence-card text-left ${selected === index ? 'evidence-card-selected' : ''}`}>
              <div className="flex items-center justify-between gap-3 text-[11px]">
                <span className="font-semibold text-zinc-200">{pretty(item.layer)}</span>
                <span className="text-zinc-400">{Math.round(item.score * 100)}%</span>
              </div>
              <div className="mt-1 text-xs text-cyan-200/80">{item.attack_type ? pretty(item.attack_type) : 'Security signal'}</div>
              <div className="mt-2 line-clamp-2 text-[11px] leading-5 text-zinc-400">{item.rationale}</div>
            </button>
          ))}
        </div>
      ) : <div className="mt-3 rounded-xl border border-emerald-300/10 bg-emerald-400/[0.025] p-3 text-xs text-emerald-200/70">No malicious evidence spans were produced.</div>}
    </div>
  )
}
