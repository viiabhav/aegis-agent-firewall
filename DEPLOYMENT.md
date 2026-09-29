# AEGIS Deployment Guide

AEGIS separates the React/Vite frontend from the Python/FastAPI security engine.

## Current production deployment

- **Frontend:** https://aegis-agent-firewall.vercel.app/
- **Backend:** https://aegis-agent-firewall-464478367532.europe-west1.run.app
- **Health:** https://aegis-agent-firewall-464478367532.europe-west1.run.app/api/health
- **Swagger:** https://aegis-agent-firewall-464478367532.europe-west1.run.app/docs

Current stack:

```text
Browser
  ↓
Vercel React/Vite frontend
  ↓ HTTPS
Google Cloud Run FastAPI backend
  ↓
AEGIS security engine
```

---

## Backend container

The root `Dockerfile` is intended for the FastAPI backend and honors the platform-provided `PORT`.

Build locally:

```bash
docker build -t aegis-api .
```

Run:

```bash
docker run --rm \
  -p 7860:7860 \
  -e GROQ_API_KEY=your_key \
  -e GROQ_MODEL=openai/gpt-oss-20b \
  -e AEGIS_CORS_ORIGINS=http://localhost:5173 \
  aegis-api
```

Health:

```text
http://localhost:7860/api/health
```

### Backend environment variables

```text
GROQ_API_KEY=...
GROQ_MODEL=openai/gpt-oss-20b
AEGIS_CORS_ORIGINS=https://YOUR-FRONTEND-DOMAIN
PORT=7860
```

Do not commit the real key. In production, prefer a managed secret store.

---

## Google Cloud Run

The production service is containerized on Cloud Run.

A source-based deployment can be performed from the repository root:

```bash
gcloud run deploy aegis-agent-firewall \
  --source . \
  --region europe-west1 \
  --allow-unauthenticated \
  --port 7860 \
  --memory 2Gi \
  --cpu 1 \
  --min-instances 0 \
  --max-instances 1 \
  --timeout 300 \
  --set-env-vars="GROQ_MODEL=openai/gpt-oss-20b,AEGIS_CORS_ORIGINS=https://aegis-agent-firewall.vercel.app"
```

Add `GROQ_API_KEY` securely through Cloud Run / Secret Manager rather than putting the real value in a shell history or repository.

---

## Frontend

The production frontend is a Vite static application deployed from the `frontend/` directory.

Production variable:

```text
VITE_API_BASE_URL=https://aegis-agent-firewall-464478367532.europe-west1.run.app
```

Build:

```bash
cd frontend
npm install
npm run build
```

Output:

```text
frontend/dist/
```

`frontend/vercel.json` provides SPA fallback routing.

---

## CORS

Production backend CORS should be restricted to the exact frontend origin:

```text
AEGIS_CORS_ORIGINS=https://aegis-agent-firewall.vercel.app
```

Avoid `*` in the final deployment.

---

## Production smoke checks

From an Incognito/InPrivate browser:

1. backend `/api/health` responds with `"status":"ok"`,
2. frontend shows `API online`,
3. frontend shows local semantic availability,
4. frontend shows LLM ready when Groq is configured,
5. safe text returns `ALLOW`,
6. direct override returns `BLOCK`,
7. indirect external content can return `SANITIZE` when useful residual content remains,
8. malicious file upload is inspected,
9. public URL inspection completes or fails cleanly,
10. multi-turn state can be enabled/reset,
11. deterministic Threat Lab replay completes,
12. Security Insights loads validation evidence,
13. no secret is returned to the browser.

---

## Secret hygiene

Before pushing or deploying:

```bash
git status
git check-ignore .env
```

`.env` must remain ignored.

Never place a real key in:

- `.env.example`
- frontend environment variables
- committed documentation
- screenshots
- demo recordings

---

## Notes

- Cloud Run may cold-start when minimum instances is `0`.
- Local MiniLM/Torch requires more memory than a tiny API, so 2 GiB is a practical starting point for this prototype.
- Groq quota/network failures should not disable deterministic defenses or replay.
