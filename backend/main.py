#!/usr/bin/env python3
"""
Flask API for Smart Village Management with JWT Authentication
Compatible with deployment platforms
"""
import os
import sys
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add src directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Import our authentication modules
from src.jwt_setup import setup_jwt
from src.auth import AuthService
from src.api.auth import auth_bp
from src.api.users_legacy import users_bp

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration - Load from environment variables
DB_CONFIG = {
    'host': os.getenv('DB_HOST', '[REDACTED_HOST]'),
    'port': int(os.getenv('DB_PORT', 25060)),
    'database': os.getenv('DB_NAME', 'defaultdb'),
    'user': os.getenv('DB_USER', 'doadmin'),
    'password': os.getenv('DB_PASSWORD', '[REDACTED]'),
    'sslmode': 'require'
}

# Create Flask app
app = Flask(__name__)

# Setup CORS
CORS(app, origins=[
    "https://wnhfnyob.manussite.space",
    "https://kqpcvvco.manussite.space",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:8000"
])

# Setup JWT
jwt = setup_jwt(app)

# Register authentication blueprint
app.register_blueprint(auth_bp)

# Register users blueprint (with RBAC protection)
app.register_blueprint(users_bp)

def get_db_connection():
    """Get database connection"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return None

def create_tables():
    """Create database tables"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
            
        cur = conn.cursor()
        
        # Create enums
        cur.execute("""
            DO $$ BEGIN
                CREATE TYPE userrole AS ENUM ('SUPER_ADMIN', 'VILLAGE_ADMIN', 'ACCOUNTING_ADMIN', 'MAINTENANCE_STAFF', 'AUDITOR', 'RESIDENT');
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
        """)
        
        cur.execute("""
            DO $$ BEGIN
                CREATE TYPE userstatus AS ENUM ('ACTIVE', 'INACTIVE', 'PENDING', 'SUSPENDED', 'DELETED');
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
        """)
        
        # Create users table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                full_name VARCHAR(100) NOT NULL,
                phone VARCHAR(20),
                hashed_password VARCHAR(255) NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                is_verified BOOLEAN DEFAULT FALSE,
                role userrole DEFAULT 'RESIDENT',
                status userstatus DEFAULT 'PENDING',
                address TEXT,
                house_number VARCHAR(20),
                id_card_number VARCHAR(20),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
                last_login TIMESTAMP WITH TIME ZONE,
                notes TEXT
            );
        """)
        
        # Create indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);")
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info("Database tables created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create tables: {e}")
        return False

def hash_password(password):
    """Hash password using SHA-256 (for backward compatibility)"""
    return hashlib.sha256(password.encode()).hexdigest()

# Initialize database tables
create_tables()

@app.route('/')
def root():
    """Root endpoint"""
    return jsonify({
        "message": "Smart Village Management API with JWT Authentication",
        "version": "2.0.0",
        "status": "running",
        "authentication": "JWT-enabled",
        "endpoints": {
            "auth": {
                "login": "POST /auth/login",
                "register": "POST /auth/register", 
                "profile": "GET /auth/me",
                "update_profile": "PATCH /auth/me",
                "refresh": "POST /auth/refresh",
                "logout": "POST /auth/logout"
            },
            "users": {
                "list": "GET /api/v1/users (Admin only)",
                "create": "POST /api/v1/users (Village Admin+)",
                "get": "GET /api/v1/users/<id> (Authenticated)",
                "update": "PUT /api/v1/users/<id> (Village Admin+)",
                "delete": "DELETE /api/v1/users/<id> (Super Admin only)",
                "stats": "GET /api/v1/users/stats (Admin only)",
                "toggle_status": "POST /api/v1/users/<id>/toggle-status (Village Admin+)"
            },
            "health": "GET /health"
        }
    })

@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        conn = get_db_connection()
        if conn:
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.close()
            conn.close()
            db_status = "connected"
        else:
            db_status = "disconnected"
    except Exception as e:
        db_status = f"error: {str(e)}"
    
    return jsonify({
        "status": "healthy",
        "database": db_status,
        "timestamp": datetime.utcnow().isoformat(),
        "authentication": "JWT-enabled"
    })

# Legacy endpoints removed - now using RBAC-protected endpoints in users_bp blueprint
# All user management endpoints are now protected with appropriate role-based access control

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)

