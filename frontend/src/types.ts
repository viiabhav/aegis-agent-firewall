export type FirewallAction = 'allow' | 'sanitize' | 'review' | 'block'

export type EvidenceItem = {
  layer: string
  attack_type: string | null
  score: number
  evidence: string
  rationale: string
  start?: number | null
  end?: number | null
  signal_id?: string | null
  turn_ids?: number[]
}

export type DetectorTrace = {
  layer: string
  status: string
  score: number
  attack_types: string[]
  reasons: string[]
  error?: string | null
  details: Record<string, unknown>
}

export type Redaction = {
  start: number
  end: number
  original: string
  replacement: string
  attack_types: string[]
  layers: string[]
}

export type FirewallDecision = {
  action: FirewallAction
  risk_score: number
  source_type: string
  trust_level: string
  attack_types: string[]
  primary_attack_type: string | null
  evidence: EvidenceItem[]
  detector_trace: DetectorTrace[]
  sanitized_content: string
  redactions: Redaction[]
  rationale: string
  requires_human_review: boolean
  provider_degraded: boolean
  metadata: Record<string, unknown>
  inspected_content?: string
}

export type Health = {
  status: string
  service: string
  llm_configured: boolean
  llm_provider: string
  llm_model: string
  llm_env_file_present: boolean
  llm_setup_command: string
  semantic_available: boolean
  replay_corpus_available: boolean
  replay_corpus: string
}

export type ReplaySummary = {
  replayed: number
  detected: number
  bypassed: number
  errors: number
  detector_gaps: number
  escalation_gaps: number
  taxonomy_mismatches: number
  security_signal_rate: number
  target_category_rate: number
}

export type ReplayResponse = {
  mode: string
  provider_generation_required: boolean
  llm_judge_enabled: boolean
  corpus: {
    schema_version: string
    name: string
    description: string
    disclaimer: string
    origin: string
    case_count: number
    categories_covered: number
    categories_total: number
  }
  redteam: Record<string, unknown>
  summary: ReplaySummary
  coverage: Record<string, Record<string, number>>
}

export type ScanHistoryItem = {
  id: string
  at: string
  input: string
  decision: FirewallDecision
}

export type ValidationSnapshot = {
  benchmark_available: boolean
  replay_report_available: boolean
  benchmark: null | {
    name: string
    disclaimer: string
    configuration: { semantic_enabled: boolean; llm_enabled: boolean; multiturn_enabled: boolean }
    summary: {
      cases: number; attack_cases: number; benign_cases: number; attack_detected: number; benign_passed: number
      overall_cases_passed: number; attack_recall: number; benign_pass_rate: number; case_pass_rate: number
      false_positives: number; false_negatives: number; benign_reviewed: number; benign_hard_stopped: number
    }
    per_category: Record<string, { cases: number; security_detected: number; security_signal_rate: number; target_label_present: number; target_label_rate: number }>
  }
  replay: null | Record<string, unknown>
}

export type LiveRedTeamEvent = { kind: string; message: string; metadata: Record<string, unknown> }
export type LiveRedTeamResponse = {
  mode: string
  events: LiveRedTeamEvent[]
  report: {
    summary: { generated: number; detected: number; target_detected: number; bypassed: number; evaluation_errors: number; evaluable: number; escalation_gaps: number; detector_gaps: number; taxonomy_mismatches: number; detection_rate: number; target_detection_rate: number; rounds_completed: number }
    coverage_by_type: Record<string, Record<string, number>>
    generation_errors: string[]
    generation_shortfalls: string[]
    attempts: Array<Record<string, unknown>>
  }
  quota_note: string
}
