
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from vulnx.core.config import settings
from vulnx.core.database import (
    check_database_connection,
    init_db,
)

from vulnx.api.assets import router as assets_router
from vulnx.api.cves import router as cves_router
from vulnx.api.scans import router as scans_router
from vulnx.api.findings import router as findings_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    lifespan=lifespan,
)


# Frontend communication configuration

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Register API routers

app.include_router(
    assets_router,
    prefix=settings.API_PREFIX,
)

app.include_router(
    cves_router,
    prefix=settings.API_PREFIX,
)

app.include_router(
    scans_router,
    prefix=settings.API_PREFIX,
)

app.include_router(
    findings_router,
    prefix=settings.API_PREFIX,
)


@app.get("/")
def root():
    return {
        "project": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "message": "VulnX API is running",
    }


@app.get("/health")
def health_check():
    database_status = check_database_connection()

    return {
        "status": "healthy" if database_status else "degraded",
        "application": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "database": (
            "connected" if database_status else "disconnected"
        ),
    }
