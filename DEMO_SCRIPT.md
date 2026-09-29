# AEGIS 3-Minute Demo Script

## 0:00–0:20 — Problem

> "AI agents increasingly read emails, documents, web pages and API responses. A malicious instruction hidden in any of that content can redirect the agent before the user sees it. AEGIS is a security gateway that inspects content before influence."

Show the **System Design** page briefly. Point to defense-in-depth and `F3 · D2`.

## 0:20–0:45 — Legitimate content

Open **Firewall → Guided demo → Clean request**.

Run inspection.

Call out:

- `ALLOW`
- low risk
- no malicious evidence
- content forwarded unchanged

## 0:45–1:10 — Direct injection

Choose **Direct override**.

Run inspection.

Call out:

- animated inspection path
- `BLOCK`
- exact evidence span
- multiple detector signals

## 1:10–1:40 — Indirect injection + surgical sanitization

Choose **Indirect web injection**.

Run inspection.

Call out:

- source is external/untrusted
- malicious instruction highlighted in **Evidence Lens**
- `SANITIZE`, not blanket block
- original vs forwarded safe content

This is the primary visual "wow" moment.

## 1:40–2:05 — Multi-turn jailbreak

Choose **Multi-turn jailbreak**.

Run each attacker turn and use **Load next attacker turn**.

Call out that individual messages can look weak but bounded conversation state correlates the staged attack.

## 2:05–2:35 — Autonomous Threat Lab

Open **Threat Lab**.

If Groq quota is healthy, run **Live simulation** and show the event stream:

`generate → test → gap → adapt`

If quota is unavailable, switch to **Replay mode** and run the 27-case provider-free campaign. Explain that resilience to provider degradation is intentional.

## 2:35–2:55 — Evidence / reliability

Open **Security Insights**.

Show:

- actual session decisions from the demo
- attack distribution / risk trend
- 27-case regression replay, 9/9 categories
- held-out project sample with explicit disclaimer

## 2:55–3:00 — Close

> "AEGIS is not another LLM wrapper. It combines deterministic defenses, local semantics, explicit trust boundaries, stateful multi-turn correlation, an optional structured judge, surgical sanitization and adaptive threat testing — while failing safely when the provider is unavailable."
