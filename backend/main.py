#!/usr/bin/env python3
"""
Pure Flask API for Smart Village Management
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

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration
DB_CONFIG = {
    'host': '[REDACTED_HOST]',
    'port': 25060,
    'database': 'defaultdb',
    'user': 'doadmin',
    'password': '[REDACTED]',
    'sslmode': 'require'
}

# Create Flask app
app = Flask(__name__)
CORS(app, origins=[
    "https://wnhfnyob.manussite.space",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:8000"
])

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
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

# Initialize database on startup
create_tables()

@app.route('/')
def root():
    """Root endpoint"""
    return jsonify({
        "message": "Smart Village Management API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "users": "/api/v1/users",
            "docs": "Flask API - No Swagger UI"
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
            status = "healthy"
        else:
            db_status = "disconnected"
            status = "unhealthy"
            
        return jsonify({
            "status": status,
            "database": db_status,
            "version": "1.0.0",
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            "status": "unhealthy",
            "database": "error",
            "error": str(e),
            "version": "1.0.0"
        }), 503

@app.route('/api/v1/users', methods=['GET'])
def get_users():
    """Get all users"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT id, username, email, full_name, phone, is_active, is_verified, 
                   role, status, address, house_number, id_card_number, 
                   created_at, updated_at, last_login, notes
            FROM users 
            ORDER BY created_at DESC
        """)
        
        users = cur.fetchall()
        cur.close()
        conn.close()
        
        # Convert datetime objects to strings
        for user in users:
            for key, value in user.items():
                if isinstance(value, datetime):
                    user[key] = value.isoformat()
        
        return jsonify({
            "users": users,
            "total": len(users)
        })
        
    except Exception as e:
        logger.error(f"Failed to get users: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/users', methods=['POST'])
def create_user():
    """Create new user"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'email', 'full_name', 'password']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Hash password
        hashed_password = hash_password(data['password'])
        
        # Insert user
        cur.execute("""
            INSERT INTO users (username, email, full_name, phone, hashed_password, 
                             role, status, address, house_number, id_card_number, notes)
            VALUES (%(username)s, %(email)s, %(full_name)s, %(phone)s, %(hashed_password)s,
                    %(role)s, %(status)s, %(address)s, %(house_number)s, %(id_card_number)s, %(notes)s)
            RETURNING id, username, email, full_name, phone, is_active, is_verified,
                     role, status, address, house_number, id_card_number, created_at, updated_at
        """, {
            'username': data['username'],
            'email': data['email'],
            'full_name': data['full_name'],
            'phone': data.get('phone'),
            'hashed_password': hashed_password,
            'role': data.get('role', 'RESIDENT'),
            'status': data.get('status', 'PENDING'),
            'address': data.get('address'),
            'house_number': data.get('house_number'),
            'id_card_number': data.get('id_card_number'),
            'notes': data.get('notes')
        })
        
        user = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        
        # Convert datetime objects to strings
        for key, value in user.items():
            if isinstance(value, datetime):
                user[key] = value.isoformat()
        
        return jsonify({
            "message": "User created successfully",
            "user": user
        }), 201
        
    except psycopg2.IntegrityError as e:
        return jsonify({"error": "Username or email already exists"}), 409
    except Exception as e:
        logger.error(f"Failed to create user: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    """Update user"""
    try:
        data = request.get_json()
        
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Build update query dynamically
        update_fields = []
        params = {'user_id': user_id}
        
        allowed_fields = ['username', 'email', 'full_name', 'phone', 'role', 'status', 
                         'address', 'house_number', 'id_card_number', 'notes', 'is_active', 'is_verified']
        
        for field in allowed_fields:
            if field in data:
                update_fields.append(f"{field} = %({field})s")
                params[field] = data[field]
        
        if 'password' in data:
            update_fields.append("hashed_password = %(hashed_password)s")
            params['hashed_password'] = hash_password(data['password'])
        
        if not update_fields:
            return jsonify({"error": "No valid fields to update"}), 400
        
        update_fields.append("updated_at = now()")
        
        query = f"""
            UPDATE users 
            SET {', '.join(update_fields)}
            WHERE id = %(user_id)s
            RETURNING id, username, email, full_name, phone, is_active, is_verified,
                     role, status, address, house_number, id_card_number, created_at, updated_at
        """
        
        cur.execute(query, params)
        user = cur.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        conn.commit()
        cur.close()
        conn.close()
        
        # Convert datetime objects to strings
        for key, value in user.items():
            if isinstance(value, datetime):
                user[key] = value.isoformat()
        
        return jsonify({
            "message": "User updated successfully",
            "user": user
        })
        
    except psycopg2.IntegrityError as e:
        return jsonify({"error": "Username or email already exists"}), 409
    except Exception as e:
        logger.error(f"Failed to update user: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete user"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        
        if cur.rowcount == 0:
            return jsonify({"error": "User not found"}), 404
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({"message": "User deleted successfully"})
        
    except Exception as e:
        logger.error(f"Failed to delete user: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/v1/users/stats')
def get_user_stats():
    """Get user statistics"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get total users
        cur.execute("SELECT COUNT(*) as total FROM users")
        total = cur.fetchone()['total']
        
        # Get users by role
        cur.execute("SELECT role, COUNT(*) as count FROM users GROUP BY role")
        by_role = {row['role']: row['count'] for row in cur.fetchall()}
        
        # Get users by status
        cur.execute("SELECT status, COUNT(*) as count FROM users GROUP BY status")
        by_status = {row['status']: row['count'] for row in cur.fetchall()}
        
        # Get active users
        cur.execute("SELECT COUNT(*) as active FROM users WHERE is_active = true")
        active = cur.fetchone()['active']
        
        cur.close()
        conn.close()
        
        return jsonify({
            "total_users": total,
            "active_users": active,
            "by_role": by_role,
            "by_status": by_status
        })
        
    except Exception as e:
        logger.error(f"Failed to get user stats: {e}")
        return jsonify({"error": str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)

