

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.dependencies import DB_PATH
from api.routes import stats, entries, chains, scan, alerts, baseline, enrichment, search, export


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Ensure all required DB tables exist before serving requests."""
    try:
        from enrichment.enrichment_manager import _init_enrichment_table
        from enrichment.baseline import BaselineManager
        _init_enrichment_table(DB_PATH)
        BaselineManager(DB_PATH)
    except Exception as exc:
        print(f"[!] Startup init warning: {exc}")
    yield


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Persistence-Hunter",
    description=(
        "Windows persistence detection, attack chain analysis, "
        "and threat enrichment API"
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------

app.include_router(stats.router,      prefix="/api",           tags=["Stats"])
app.include_router(entries.router,    prefix="/api/entries",   tags=["Entries"])
app.include_router(chains.router,     prefix="/api/chains",    tags=["Chains"])
app.include_router(scan.router,       prefix="/api/scan",      tags=["Scan"])
app.include_router(alerts.router,     prefix="/api/alerts",    tags=["Alerts"])
app.include_router(baseline.router,   prefix="/api/baseline",  tags=["Baseline"])
app.include_router(enrichment.router, prefix="/api/enrich",    tags=["Enrichment"])
app.include_router(search.router,     prefix="/api/search",    tags=["Search"])
app.include_router(export.router,     prefix="/api/export",    tags=["Export"])
from .routes.scores import router as scores_router
app.include_router(scores_router, prefix="/api")