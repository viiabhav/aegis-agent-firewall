# AEGIS Architecture Notes

## Request path

1. **Ingestion** extracts content from text, URL, PDF, DOCX, email, HTML, API payloads, source code and OCR/image inputs.
2. **Normalization** canonicalizes Unicode and surfaces reversible encodings before detection.
3. **Heuristic detection** produces cheap, explainable high-signal findings.
4. **Semantic detection** compares bounded segments with an original attack-prototype corpus using local MiniLM embeddings.
5. **Trust boundary** marks external/retrieved content as untrusted and adds escalation signals for agent-directed imperatives.
6. **Multi-turn state** correlates staged triggers, role setup, split payloads and later activation.
7. **LLM judge** is invoked only for escalated cases and returns strict structured JSON. It receives inspected content as inert data and has no tools.
8. **Decision engine** fuses independent evidence into `ALLOW`, `SANITIZE`, `REVIEW` or `BLOCK`.
9. **Sanitizer** surgically removes mapped malicious spans when useful external content can be preserved.

## Autonomous red-team path

`plan → generate → test → classify outcome → analyze gap → focus next round`

The live generator is intentionally provider-dependent. Deterministic replay uses persisted historical attacks so regression validation continues without generation access.

## Fail-safe policy

- Provider unavailable + strong deterministic evidence → `BLOCK` or `SANITIZE`
- Provider unavailable + ambiguous escalated cues → `REVIEW`
- Provider disagreement with strong deterministic evidence → `REVIEW`
- No material signal → `ALLOW`

## Trust model

AEGIS is a **content firewall**, not an authorization system. Production agents should still enforce tool allowlists, IAM, sandboxing, least privilege, network boundaries and transaction confirmation independently of AEGIS.
