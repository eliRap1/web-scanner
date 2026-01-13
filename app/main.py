from fastapi import FastAPI
from contextlib import asynccontextmanager
from scanner.worker import start_worker 
from security.middleware import auth_middleware
from api.auth.login import router as login_router
from api.auth.register import router as register_router
from scans.scans_router import router as scans_router
from db.database import init_database, ensure_admin_exists
from fastapi.middleware.cors import CORSMiddleware
from scanner.task_queue import recover_stuck_scans_on_startup

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_database()
    ensure_admin_exists()
    recover_stuck_scans_on_startup()
    start_worker()
    yield
    # Shutdown (if needed)


app = FastAPI(
    title="Web Scanner API",
    version="1.0.0",
    lifespan=lifespan
)

# ---------- Middleware ----------
app.middleware("http")(auth_middleware)

# ---------- Routers ----------
app.include_router(login_router, tags=["Auth"])
app.include_router(register_router, tags=["Auth"])
app.include_router(scans_router, prefix="/scan", tags=["scanner"])

# ---------- Root ----------
@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "web-scanner",
        "docs": "/docs"
    }
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
