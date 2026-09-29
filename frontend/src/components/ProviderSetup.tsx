import { BrainCircuit, CheckCircle2, Copy, RefreshCw, SquareTerminal, X } from 'lucide-react'
import { useState } from 'react'
import type { Health } from '../types'

export function ProviderSetup({ health, onClose, onRefresh }: { health: Health | null; onClose: () => void; onRefresh: () => Promise<void> }) {
  const [copied, setCopied] = useState(false)
  const [checking, setChecking] = useState(false)
  const command = health?.llm_setup_command || '.\\scripts\\configure_llm.ps1'

  async function copyCommand() {
    try {
      await navigator.clipboard.writeText(command)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1600)
    } catch {
      setCopied(false)
    }
  }

  async function recheck() {
    setChecking(true)
    try { await onRefresh() } finally { setChecking(false) }
  }

  return (
    <section className="provider-card" aria-labelledby="provider-setup-title">
      <div className="flex items-start gap-3">
        <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-cyan-300/15 bg-cyan-400/[0.06]">
          <BrainCircuit className="h-4 w-4 text-cyan-200" aria-hidden="true" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 id="provider-setup-title" className="text-sm font-semibold text-white">LLM Judge provider</h2>
              <p className="mt-1 text-xs leading-5 text-zinc-300">
                {health?.llm_configured
                  ? `Ready · ${health.llm_provider.toUpperCase()} · ${health.llm_model}`
                  : 'Not configured. AEGIS remains fully usable with deterministic + local semantic defenses.'}
              </p>
            </div>
            <button type="button" onClick={onClose} className="icon-button" aria-label="Close LLM provider setup">
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>

          {health?.llm_configured ? (
            <div className="mt-4 flex items-center gap-2 rounded-xl border border-emerald-300/15 bg-emerald-400/[0.05] px-3 py-2 text-xs text-emerald-100">
              <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
              Provider detected. You can enable the LLM Judge toggle above.
            </div>
          ) : (
            <>
              <ol className="mt-4 space-y-2 text-xs leading-5 text-zinc-300">
                <li><span className="step-number">1</span> Open a PowerShell in the project root.</li>
                <li><span className="step-number">2</span> Run the secure local setup script below. Your key is never sent to the browser.</li>
                <li><span className="step-number">3</span> Return here and choose <strong className="text-zinc-100">Recheck provider</strong>.</li>
              </ol>
              <div className="mt-4 flex flex-col gap-2 sm:flex-row">
                <code className="provider-command"><SquareTerminal className="h-4 w-4 shrink-0 text-cyan-300" aria-hidden="true" />{command}</code>
                <button type="button" className="secondary-button" onClick={copyCommand}>
                  <Copy className="h-4 w-4" aria-hidden="true" />{copied ? 'Copied' : 'Copy command'}
                </button>
              </div>
            </>
          )}

          <button type="button" className="secondary-button mt-3" onClick={recheck} disabled={checking}>
            <RefreshCw className={`h-4 w-4 ${checking ? 'animate-spin' : ''}`} aria-hidden="true" />
            {checking ? 'Checking…' : 'Recheck provider'}
          </button>
        </div>
      </div>
    </section>
  )
}
