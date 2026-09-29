# Deployment Guide

AEGIS separates the React frontend from the Python/FastAPI security engine.

## Recommended competition deployment

- **Frontend:** Vercel (Vite static site)
- **Backend:** a container host with enough memory for Python + sentence-transformers/Torch. A Docker configuration is included.

Because MiniLM/Torch is heavier than a tiny API, verify memory on the chosen free tier before using it for the final judge URL.

## Backend container

Build locally:

```bash
docker build -t aegis-api .
docker run --rm -p 7860:7860 -e GROQ_API_KEY=... aegis-api
```

Health:

```text
http://localhost:7860/api/health
```

Set backend environment variables on the hosting provider:

```text
GROQ_API_KEY=...
GROQ_MODEL=openai/gpt-oss-20b
AEGIS_CORS_ORIGINS=https://YOUR-FRONTEND-DOMAIN
PORT=7860
```

Do not commit the real key.

## Frontend

Set:

```text
VITE_API_BASE_URL=https://YOUR-BACKEND-DOMAIN
```

Then from `frontend/`:

```bash
npm install
npm run build
```

`frontend/vercel.json` includes SPA fallback routing.

## Production smoke checks

From an incognito browser:

1. `/api/health` responds on the public backend.
2. The public frontend shows `API online`.
3. Clean text returns `ALLOW`.
4. Direct override returns `BLOCK`.
5. Indirect external content returns `SANITIZE` when useful residual content remains.
6. Red-team replay works with the Groq key removed.
7. No secret appears in browser devtools/network responses.
