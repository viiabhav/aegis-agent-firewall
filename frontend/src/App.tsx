import { useCallback, useEffect, useState } from 'react'
import { Brand } from './components/Brand'
import { Sidebar, type PageKey } from './components/Sidebar'
import { Topbar } from './components/Topbar'
import { getHealth } from './lib/api'
import { ArchitecturePage } from './pages/ArchitecturePage'
import { FirewallPage } from './pages/FirewallPage'
import { PosturePage } from './pages/PosturePage'
import { RedTeamPage } from './pages/RedTeamPage'
import type { Health, ScanHistoryItem } from './types'

const mobileNav: Array<[PageKey, string]> = [['firewall', 'Firewall'], ['redteam', 'Threat Lab'], ['posture', 'Insights'], ['architecture', 'Design']]

export default function App() {
  const [page, setPage] = useState<PageKey>('firewall')
  const [health, setHealth] = useState<Health | null>(null)
  const [history, setHistory] = useState<ScanHistoryItem[]>(() => {
    try {
      const stored = window.localStorage.getItem('aegis.scanHistory')
      return stored ? (JSON.parse(stored) as ScanHistoryItem[]).slice(-100) : []
    } catch { return [] }
  })

  const refreshHealth = useCallback(async () => {
    try { setHealth(await getHealth()) } catch { setHealth(null) }
  }, [])

  useEffect(() => {
    let active = true
    getHealth().then((value) => active && setHealth(value)).catch(() => active && setHealth(null))
    const timer = window.setInterval(() => getHealth().then((value) => active && setHealth(value)).catch(() => {}), 15000)
    return () => { active = false; window.clearInterval(timer) }
  }, [])

  useEffect(() => {
    try { window.localStorage.setItem('aegis.scanHistory', JSON.stringify(history.slice(-100))) } catch { /* storage is optional */ }
  }, [history])

  function addHistory(item: ScanHistoryItem) {
    setHistory((current) => [...current.slice(-99), item])
  }

  function clearHistory() {
    setHistory([])
    try { window.localStorage.removeItem('aegis.scanHistory') } catch { /* storage is optional */ }
  }

  return (
    <div className="min-h-screen bg-[#080a0f] text-zinc-100">
      <a href="#main-content" className="skip-link">Skip to main content</a>
      <div className="aegis-background" aria-hidden="true" />
      <div className="relative z-10 flex min-h-screen">
        <Sidebar page={page} onChange={setPage} />
        <main id="main-content" className="min-w-0 flex-1" tabIndex={-1}>
          <div className="flex h-16 items-center border-b border-white/7 px-5 lg:hidden"><Brand /></div>
          <Topbar health={health} />
          {page === 'firewall' && <FirewallPage health={health} onHistory={addHistory} onRefreshHealth={refreshHealth} />}
          {page === 'redteam' && <RedTeamPage health={health} />}
          {page === 'posture' && <PosturePage history={history} onClearHistory={clearHistory} />}
          {page === 'architecture' && <ArchitecturePage health={health} />}
          <div className="h-20 lg:hidden" />
        </main>
      </div>
      <nav aria-label="Mobile workspace" className="fixed inset-x-3 bottom-3 z-50 flex rounded-2xl border border-white/10 bg-[#0d1016]/98 p-1.5 shadow-2xl backdrop-blur-xl lg:hidden">
        {mobileNav.map(([id, label]) => (
          <button type="button" key={id} onClick={() => setPage(id)} aria-current={page === id ? 'page' : undefined} className={`flex-1 rounded-xl px-2 py-2.5 text-[11px] font-semibold ${page === id ? 'bg-white/[0.09] text-cyan-200' : 'text-zinc-400'}`}>
            {label}
          </button>
        ))}
      </nav>
    </div>
  )
}
