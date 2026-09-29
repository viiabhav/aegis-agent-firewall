from __future__ import annotations

from contextlib import asynccontextmanager
import os
from pathlib import Path
import shutil
import tempfile
from typing import Annotated

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool

from aegis.agents import (
    FirewallEvaluator,
    GroqAttackGenerator,
    GroqBypassAnalyzer,
    RedTeamAgent,
    ReplayCorpus,
    run_replay,
)
from aegis.ingestion.dispatcher import ingest_file, ingest_url
from aegis.detection import AttackType, GroqJudgeProvider, LLMJudge
from aegis.models import InputSource

from .models import LiveRedTeamRequest, ReplayRequest, ResetConversationRequest, ScanRequest, UrlScanRequest
from .runtime import (
    benchmark_report_path,
    build_engine,
    conversation_engine,
    llm_judge,
    llm_status,
    replay_corpus_path,
    replay_report_path,
    reset_conversation,
    semantic_detector,
    validate_public_url,
)


MAX_UPLOAD_BYTES = 15 * 1024 * 1024


def _cors_origins() -> list[str]:
    raw = os.getenv(
        "AEGIS_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    )
    return [item.strip() for item in raw.split(",") if item.strip()]


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield


app = FastAPI(
    title="AEGIS Prompt Injection Firewall API",
    version="1.0.0",
    description="API adapter for the AEGIS defense-in-depth decision engine.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict:
    corpus = replay_corpus_path()
    return {
        "status": "ok",
        "service": "aegis-api",
        **llm_status(),
        "semantic_available": True,
        "replay_corpus_available": corpus.is_file(),
        "replay_corpus": str(corpus.name),
    }


@app.post("/api/scan")
async def scan(request: ScanRequest) -> dict:
    try:
        source = InputSource(request.source_type)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Unsupported source_type: {request.source_type}") from exc

    if request.track_conversation:
        conversation_id = request.conversation_id or "default"
        engine = conversation_engine(
            conversation_id,
            use_semantic=request.use_semantic,
            use_llm=request.use_llm,
        )
        decision = await run_in_threadpool(
            engine.inspect_text,
            request.content,
            source,
            track_conversation=True,
        )
    else:
        engine = build_engine(
            use_semantic=request.use_semantic,
            use_llm=request.use_llm,
            multiturn=False,
        )
        decision = await run_in_threadpool(
            engine.inspect_text,
            request.content,
            source,
            track_conversation=False,
        )
    payload = decision.to_dict()
    payload["inspected_content"] = request.content
    return payload


@app.post("/api/scan/url")
async def scan_url(request: UrlScanRequest) -> dict:
    try:
        url = await run_in_threadpool(validate_public_url, request.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    engine = build_engine(use_semantic=request.use_semantic, use_llm=request.use_llm, multiturn=False)
    try:
        document = await run_in_threadpool(ingest_url, url)
        decision = await run_in_threadpool(engine.inspect_document, document, track_conversation=False)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not inspect URL: {type(exc).__name__}: {exc}") from exc
    payload = decision.to_dict()
    payload["inspected_content"] = document.normalized.canonical_text[:100_000]
    return payload


@app.post("/api/scan/file")
async def scan_file(
    file: Annotated[UploadFile, File(description="PDF, DOCX, email, HTML, text, code, JSON, or image")],
    use_semantic: Annotated[bool, Form()] = True,
    use_llm: Annotated[bool, Form()] = False,
) -> dict:
    filename = Path(file.filename or "upload.txt").name
    suffix = Path(filename).suffix
    with tempfile.NamedTemporaryFile(prefix="aegis_", suffix=suffix, delete=False) as handle:
        temp_path = Path(handle.name)
        total = 0
        try:
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="Upload exceeds the 15 MB prototype limit")
                handle.write(chunk)
        finally:
            await file.close()

    try:
        engine = build_engine(use_semantic=use_semantic, use_llm=use_llm, multiturn=False)
        document = await run_in_threadpool(ingest_file, temp_path)
        decision = await run_in_threadpool(engine.inspect_document, document, track_conversation=False)
        payload = decision.to_dict()
        payload.setdefault("metadata", {})["filename"] = filename
        payload["inspected_content"] = document.normalized.canonical_text[:100_000]
        return payload
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not inspect file: {type(exc).__name__}: {exc}") from exc
    finally:
        temp_path.unlink(missing_ok=True)


@app.post("/api/conversation/reset")
def reset(request: ResetConversationRequest) -> dict:
    return {"reset": reset_conversation(request.conversation_id), "conversation_id": request.conversation_id}


@app.post("/api/redteam/replay")
async def redteam_replay(request: ReplayRequest) -> dict:
    corpus_path = replay_corpus_path()
    if not corpus_path.is_file():
        raise HTTPException(status_code=404, detail="Replay corpus not found")

    def _run() -> dict:
        corpus = ReplayCorpus.load(corpus_path)
        evaluator = FirewallEvaluator(
            semantic_detector=semantic_detector() if request.use_semantic else None,
            llm_judge=None,
            audit_bypasses_with_forced_llm=False,
            count_escalation_without_llm=True,
        )
        result = run_replay(corpus, evaluator)
        payload = result.to_dict()
        payload["summary"] = {
            "replayed": result.report.generated_count,
            "detected": result.report.detected_count,
            "bypassed": result.report.bypass_count,
            "errors": result.report.evaluation_error_count,
            "detector_gaps": result.report.detector_gap_count,
            "escalation_gaps": result.report.escalation_gap_count,
            "taxonomy_mismatches": result.report.taxonomy_mismatch_count,
            "security_signal_rate": result.report.detection_rate,
            "target_category_rate": result.report.target_detection_rate,
        }
        payload["coverage"] = result.report.coverage_by_type()
        return payload

    return await run_in_threadpool(_run)


@app.get("/api/validation")
def validation_snapshot() -> dict:
    def read_json(path: Path) -> dict | None:
        if not path.is_file():
            return None
        try:
            import json
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None

    benchmark = read_json(benchmark_report_path())
    replay = read_json(replay_report_path())
    return {
        "benchmark": benchmark,
        "replay": replay,
        "benchmark_available": benchmark is not None,
        "replay_report_available": replay is not None,
    }


@app.post("/api/redteam/live")
async def redteam_live(request: LiveRedTeamRequest) -> dict:
    refresh = llm_status()
    if not refresh.get("llm_configured"):
        raise HTTPException(status_code=409, detail="Groq is not configured; use deterministic replay instead")

    try:
        attack_types = [AttackType(item) for item in request.attack_types]
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Unknown attack type: {exc}") from exc

    def _run() -> dict:
        events: list[dict] = []

        def capture(event) -> None:
            events.append({
                "kind": event.kind,
                "message": event.message,
                "metadata": event.metadata,
            })

        judge_provider = GroqJudgeProvider(
            timeout=12.0,
            max_retries=1,
            retry_backoff_seconds=0.5,
            max_retry_delay_seconds=2.0,
        )
        generator_provider = GroqJudgeProvider(
            timeout=12.0,
            reasoning_effort="low",
            max_retries=1,
            retry_backoff_seconds=0.5,
            max_retry_delay_seconds=2.0,
            max_completion_tokens=900,
        )
        generator = GroqAttackGenerator(
            generator_provider,
            max_refill_calls=1,
            max_categories_per_call=2,
        )
        analyzer = GroqBypassAnalyzer(generator_provider)
        evaluator = FirewallEvaluator(
            semantic_detector=semantic_detector(),
            llm_judge=LLMJudge(judge_provider),
            audit_bypasses_with_forced_llm=True,
        )
        agent = RedTeamAgent(
            generator,
            evaluator,
            analyzer=analyzer,
            max_generation_retries=0,
            on_event=capture,
        )
        report = agent.run(
            attack_types,
            variants_per_type=request.variants_per_type,
            rounds=request.rounds,
        )
        return {
            "mode": "live_agent",
            "events": events,
            "report": report.to_dict(),
            "quota_note": "Live generation is provider-dependent; deterministic replay remains the stable fallback.",
        }

    return await run_in_threadpool(_run)
