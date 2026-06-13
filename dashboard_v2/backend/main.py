from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .db import init_db
from .routers import agents, compliance, env, events, hitl, metrics, report, sessions


ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = ROOT / "frontend"

app = FastAPI(title="ASF Compliance Dashboard")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(agents.router)
app.include_router(events.router)
app.include_router(hitl.router)
app.include_router(sessions.router)
app.include_router(metrics.router)
app.include_router(compliance.router)
app.include_router(report.router)
app.include_router(env.router)

app.mount("/assets", StaticFiles(directory=FRONTEND_DIR), name="assets")
app.mount("/sections", StaticFiles(directory=FRONTEND_DIR / "sections"), name="sections")


@app.on_event("startup")
async def startup() -> None:
    await init_db()


@app.get("/")
async def index():
    return RedirectResponse(url="/overview", status_code=307)


def _page(name: str) -> FileResponse:
    return FileResponse(
        FRONTEND_DIR / f"{name}.html",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.get("/overview")
async def overview_page():
    return _page("overview")


@app.get("/compliance")
async def compliance_page():
    return _page("compliance")


@app.get("/hitl")
async def hitl_page():
    return _page("hitl")


@app.get("/sessions")
async def sessions_page():
    return _page("sessions")


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="0.0.0.0", port=8080, reload=True)
