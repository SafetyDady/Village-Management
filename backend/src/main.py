from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
from contextlib import asynccontextmanager

from .config import settings
from .database import test_connection, create_tables
from .api import users

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan events
    """
    # Startup
    logger.info("Starting Smart Village Management API...")
    
    # Test database connection
    if not test_connection():
        logger.error("Database connection failed!")
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    # Create tables
    if not create_tables():
        logger.error("Failed to create database tables!")
        raise HTTPException(status_code=500, detail="Failed to create database tables")
    
    logger.info("Database connection and tables created successfully")
    logger.info("Smart Village Management API started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Smart Village Management API...")

# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Smart Village Management System API",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Include routers
app.include_router(users.router, prefix="/api/v1/users", tags=["users"])

@app.get("/")
async def root():
    """
    Root endpoint
    """
    return {
        "message": "Smart Village Management API",
        "version": settings.app_version,
        "status": "running"
    }

@app.get("/health")
async def health_check():
    """
    Health check endpoint
    """
    try:
        db_status = test_connection()
        return {
            "status": "healthy" if db_status else "unhealthy",
            "database": "connected" if db_status else "disconnected",
            "version": settings.app_version
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "database": "error",
                "error": str(e),
                "version": settings.app_version
            }
        )

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """
    Global exception handler
    """
    logger.error(f"Global exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": str(exc) if settings.debug else "An error occurred"
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level="info"
    )

