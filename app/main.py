"""OPTISEC Eternal Core — standalone FastAPI app for the hybrid storage
foundation (TimescaleDB + MinIO) and the initial mock recon engine.
Run with: uvicorn app.main:app --reload --port 8100
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.endpoints import router as v1_router
from app.services.storage.hybrid_repository import start_archive_scheduler

app = FastAPI(
    title="OPTISEC Eternal Core",
    description="Hybrid TimescaleDB + MinIO archive core, foundation for the Recon engine.",
    version="1.0.0",
)

# allow_origins=["*"] + allow_credentials=True is an invalid combination per
# the CORS spec (a wildcard origin can't be paired with credentialed
# requests) and browsers reject it outright. It was also unnecessary here:
# Eternal Core has no cookie/session-based auth for CORS credentials to
# carry -- every endpoint authenticates via a header (HTTP Basic / API key),
# which a cross-origin page can't forge on the browser's behalf regardless
# of this setting. So allow_credentials is simply False; allow_origins stays
# "*" since there's no browser frontend or trusted-origin list for this
# subsystem to restrict to.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(v1_router, prefix="/api/v1")

_scheduler = None


@app.on_event("startup")
def _startup():
    global _scheduler
    _scheduler = start_archive_scheduler()


@app.on_event("shutdown")
def _shutdown():
    if _scheduler:
        _scheduler.shutdown(wait=False)


@app.get("/health")
async def health():
    return {"status": "ok"}
