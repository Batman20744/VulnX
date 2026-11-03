
from contextlib import asynccontextmanager

from fastapi import FastAPI

from vulnx.core.config import settings
from vulnx.core.database import (
    check_database_connection,
    init_db,
)

from vulnx.api.assets import router as assets_router
from vulnx.api.cves import router as cves_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables when application starts.
    init_db()
    yield


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=settings.APP_DESCRIPTION,
    lifespan=lifespan,
)


# Asset Inventory API
app.include_router(
    assets_router,
    prefix=settings.API_PREFIX,
)


# CVE Intelligence API
app.include_router(
    cves_router,
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
