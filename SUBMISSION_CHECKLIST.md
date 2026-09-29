# Final Submission Checklist

## Code / repository

- [ ] Create public GitHub repository
- [ ] Push the final frozen code
- [ ] Verify `.env` is NOT tracked
- [ ] Search repository for `gsk_` and other secrets
- [ ] Keep `.env.example` placeholder-only
- [ ] Confirm `README.md` renders correctly on GitHub
- [ ] Add 3–5 UI screenshots to `docs/screenshots/`

## Quality gates

- [ ] `python -m pytest` passes
- [ ] `python scripts/redteam_replay.py --no-semantic` completes
- [ ] `python scripts/benchmark.py --no-semantic` completes
- [ ] `cd frontend && npm run build` succeeds
- [ ] Clean / block / sanitize / review flows tested manually
- [ ] File upload tested
- [ ] URL scan tested
- [ ] Multi-turn demo tested
- [ ] LLM provider degradation tested

## Deployment

- [ ] Public backend URL responds at `/api/health`
- [ ] Public frontend URL loads in incognito
- [ ] CORS only allows intended frontend origin
- [ ] Groq key configured only on backend host
- [ ] Replay mode works without Groq

## Competition claims

- [ ] Declare **F3 / D2**
- [ ] Do not claim D3 from OCR/image support
- [ ] Label red-team replay as regression corpus, not benchmark
- [ ] Label held-out project sample as small project evaluation, not external benchmark
- [ ] Do not quote a live-red-team percentage as general accuracy

## Submission package

- [ ] Public GitHub URL
- [ ] Accessible deployed demo URL
- [ ] Pitch deck
- [ ] 2–4 minute demo video
- [ ] Final Unstop submission fields completed before deadline


## Pitch deck source
- [ ] Build the final deck from `PITCH_DECK_OUTLINE.md`; use real AEGIS screenshots and only the scoped metrics documented there.
