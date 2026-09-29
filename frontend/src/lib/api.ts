import type { FirewallDecision, Health, LiveRedTeamResponse, ReplayResponse, ValidationSnapshot } from '../types'

const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

async function parse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let message = `Request failed (${response.status})`
    try {
      const body = await response.json()
      message = body.detail ?? message
    } catch {
      // keep fallback message
    }
    throw new Error(message)
  }
  return response.json() as Promise<T>
}

export async function getHealth(): Promise<Health> {
  return parse(await fetch(`${API_BASE}/api/health`))
}

export async function scanText(payload: {
  content: string
  source_type: string
  use_semantic: boolean
  use_llm: boolean
  conversation_id?: string
  track_conversation?: boolean
}): Promise<FirewallDecision> {
  return parse(await fetch(`${API_BASE}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }))
}

export async function scanUrl(payload: {
  url: string
  use_semantic: boolean
  use_llm: boolean
}): Promise<FirewallDecision> {
  return parse(await fetch(`${API_BASE}/api/scan/url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }))
}

export async function scanFile(file: File, useSemantic: boolean, useLlm: boolean): Promise<FirewallDecision> {
  const data = new FormData()
  data.set('file', file)
  data.set('use_semantic', String(useSemantic))
  data.set('use_llm', String(useLlm))
  return parse(await fetch(`${API_BASE}/api/scan/file`, { method: 'POST', body: data }))
}

export async function resetConversation(conversationId: string): Promise<void> {
  await parse(await fetch(`${API_BASE}/api/conversation/reset`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ conversation_id: conversationId }),
  }))
}

export async function runReplay(useSemantic: boolean): Promise<ReplayResponse> {
  return parse(await fetch(`${API_BASE}/api/redteam/replay`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ use_semantic: useSemantic }),
  }))
}


export async function getValidation(): Promise<ValidationSnapshot> {
  return parse(await fetch(`${API_BASE}/api/validation`))
}

export async function runLiveRedTeam(attackTypes: string[]): Promise<LiveRedTeamResponse> {
  return parse(await fetch(`${API_BASE}/api/redteam/live`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ attack_types: attackTypes, variants_per_type: 1, rounds: 1 }),
  }))
}
