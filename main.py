from fastapi import FastAPI
from contextlib import asynccontextmanager

from security.middleware import auth_middleware
from api.auth.login import router as login_router
from api.auth.register import router as register_router
#from api.scans.routes import router as scans_router
from db.database import init_database, ensure_admin_exists


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_database()
    ensure_admin_exists()
    yield
    # Shutdown (אם תרצה בהמשך)


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
#app.include_router(scans_router, prefix="/scans", tags=["Scans"])

# ---------- Root ----------
@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "web-scanner",
        "docs": "/docs"
    }
