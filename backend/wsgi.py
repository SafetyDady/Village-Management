#!/usr/bin/env python3
"""
WSGI entry point for deployment
"""
import os
import sys
from pathlib import Path

# Add current directory and src to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))
sys.path.insert(0, str(current_dir / "src"))

# Set environment variables for production
os.environ.setdefault("DATABASE_URL", "postgresql://doadmin:[REDACTED]@[REDACTED_HOST]:25060/defaultdb?sslmode=require")
os.environ.setdefault("DB_HOST", "[REDACTED_HOST]")
os.environ.setdefault("DB_PORT", "25060")
os.environ.setdefault("DB_NAME", "defaultdb")
os.environ.setdefault("DB_USER", "doadmin")
os.environ.setdefault("DB_PASSWORD", "[REDACTED]")
os.environ.setdefault("APP_NAME", "Smart Village Management API")
os.environ.setdefault("APP_VERSION", "1.0.0")
os.environ.setdefault("DEBUG", "False")
os.environ.setdefault("SECRET_KEY", "smart-village-secret-key-production-2024")

try:
    from src.main import app
    application = app
    
    if __name__ == "__main__":
        import uvicorn
        port = int(os.environ.get("PORT", 8000))
        uvicorn.run(app, host="0.0.0.0", port=port)
        
except ImportError as e:
    print(f"Import error: {e}")
    # Fallback Flask app for compatibility
    from flask import Flask, jsonify
    
    application = Flask(__name__)
    
    @application.route('/')
    def root():
        return jsonify({
            "message": "Smart Village Management API (Flask Fallback)",
            "status": "error",
            "error": "FastAPI import failed"
        })
    
    @application.route('/health')
    def health():
        return jsonify({
            "status": "unhealthy",
            "database": "unknown",
            "error": "FastAPI import failed"
        })

# For gunicorn
app = application

