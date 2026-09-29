# AEGIS Pitch Deck Outline

Use this as the source for the final 8–10 slide presentation.

## 1. Title — AEGIS
**Agentic Prompt Injection Firewall**  
Inspect before influence.

One-line value proposition: A defense-in-depth gateway that intercepts direct and indirect prompt injection before content can influence an AI agent, then returns an explainable ALLOW / SANITIZE / REVIEW / BLOCK decision.

## 2. Problem
AI agents increasingly read untrusted emails, documents, webpages, API responses and tool outputs. Those inputs can contain instructions that compete with the agent's actual task, request secrets, abuse tools, poison context or stage multi-turn jailbreaks.

Show the trust-boundary problem: **external content is data, but an LLM may interpret it as instruction.**

## 3. Why conventional filtering is insufficient
- Regex alone misses paraphrases and staged attacks.
- An LLM classifier alone is expensive, provider-dependent and itself exposed to adversarial content.
- Blanket blocking destroys useful content.
- Single-turn scanners miss staged jailbreaks.

AEGIS uses independent layers with different failure modes.

## 4. AEGIS architecture
Show the runtime path:
Ingestion + normalization → heuristic → semantic → trust boundary → multi-turn → optional structured LLM judge → risk fusion → ALLOW / SANITIZE / REVIEW / BLOCK.

Highlight: **LLM ≠ authority**. Provider failure never defaults to allow.

## 5. Product experience
Use the React AEGIS Console screenshots.
- Live inspection workspace
- Animated detector journey
- Evidence Lens
- Surgical before/after sanitization
- Conversation memory
- Security Insights

The strongest visual is indirect injection being removed while legitimate document content survives.

## 6. Agentic differentiator — Threat Lab
Show the adaptive validation loop:
Generate scenario → test firewall → identify gaps → analyze outcome → focus the next round.

When provider quota is unavailable, deterministic replay of 27 persisted regression cases keeps validation available.

## 7. Coverage + evidence
State only scoped evidence:
- Implements all 9 requested attack families.
- 27-case development regression replay: 9/9 categories, 27/27 security-signaled, 0 bypasses in the frozen replay artifact. **Not an independent benchmark.**
- 60-case post-calibration project sample in minimal offline mode: 86.7% attack capture, 73.3% benign auto-allow, 0 benign hard-stops. **Small project sample, not calibrated accuracy.**
- 257 automated tests.

## 8. Enterprise / responsible-AI design
- Explicit trust boundaries for retrieved content.
- Surgical sanitization instead of blanket blocking where possible.
- Human REVIEW path for ambiguity.
- Provider-degraded fail-safe behavior.
- No automatic self-modification from red-team suggestions.
- URL inspection rejects private/localhost targets.
- API keys stay server-side.

## 9. Scope and scalability
Declare **F3 / D2**.
- All nine attack families implemented; F3 requires at least seven.
- Structured/textual reliability is the core D2 claim.
- OCR/image ingestion is a bonus path, not claimed as D3.

Future production hardening: authorization/tool policy integration, persistent event store, organization policy registry, larger independent benchmark, distributed inference.

## 10. Closing
**AEGIS turns prompt injection from an invisible prompt problem into a visible, inspectable security control.**

End on the AEGIS Console decision screen + tagline: **Inspect before influence.**
