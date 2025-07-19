"""
Authentication module for Village Management System
Implements JWT-based authentication using Flask-JWT-Extended
"""
import os
import bcrypt
from datetime import datetime, timedelta
from flask import jsonify, request
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from src.models import User
from src.database import get_db_connection
from psycopg2.extras import RealDictCursor


class AuthService:
    """Authentication service class"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    
    @staticmethod
    def get_user_by_email(email: str) -> dict:
        """Get user by email"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor(cursor_factory=RealDictCursor)
                cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            print(f"Error getting user by email: {e}")
            return None
    
    @staticmethod
    def get_user_by_id(user_id: int) -> dict:
        """Get user by ID"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor(cursor_factory=RealDictCursor)
                cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            print(f"Error getting user by ID: {e}")
            return None
    
    @staticmethod
    def update_last_login(user_id: int):
        """Update user's last login timestamp"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET last_login = NOW() WHERE id = %s",
                    (user_id,)
                )
                conn.commit()
        except Exception as e:
            print(f"Error updating last login: {e}")
    
    @staticmethod
    def authenticate_user(email: str, password: str) -> dict:
        """Authenticate user with email and password"""
        user = AuthService.get_user_by_email(email)
        
        if not user:
            return None
        
        if not user.get('is_active', False):
            return None
        
        if not AuthService.verify_password(password, user['hashed_password']):
            return None
        
        # Update last login
        AuthService.update_last_login(user['id'])
        
        return user
    
    @staticmethod
    def create_tokens(user: dict) -> dict:
        """Create access and refresh tokens for user"""
        # Create token payload
        additional_claims = {
            "role": user['role'],
            "email": user['email'],
            "full_name": user['full_name']
        }
        
        access_token = create_access_token(
            identity=user['id'],
            additional_claims=additional_claims
        )
        
        refresh_token = create_refresh_token(
            identity=user['id'],
            additional_claims=additional_claims
        )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600))
        }


def setup_jwt(app):
    """Setup JWT configuration for Flask app"""
    
    # JWT Configuration
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600)))
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(seconds=int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES', 2592000)))
    
    # Initialize JWT Manager
    jwt = JWTManager(app)
    
    # JWT Error Handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({
            'error': 'token_expired',
            'message': 'The token has expired'
        }), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({
            'error': 'invalid_token',
            'message': 'Invalid token'
        }), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({
            'error': 'authorization_required',
            'message': 'Request does not contain an access token'
        }), 401
    
    return jwt


def require_role(allowed_roles):
    """Decorator to require specific roles"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            # This will be called inside a @jwt_required() decorated function
            current_user_id = get_jwt_identity()
            claims = get_jwt()
            user_role = claims.get('role')
            
            if user_role not in allowed_roles:
                return jsonify({
                    'error': 'insufficient_permissions',
                    'message': 'You do not have permission to access this resource'
                }), 403
            
            return f(*args, **kwargs)
        
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


# Role-based decorators
def require_super_admin(f):
    """Require SUPER_ADMIN role"""
    return require_role(['SUPER_ADMIN'])(f)

def require_village_admin(f):
    """Require VILLAGE_ADMIN or higher"""
    return require_role(['SUPER_ADMIN', 'VILLAGE_ADMIN'])(f)

def require_accounting_admin(f):
    """Require ACCOUNTING_ADMIN or higher"""
    return require_role(['SUPER_ADMIN', 'VILLAGE_ADMIN', 'ACCOUNTING_ADMIN'])(f)

def require_any_admin(f):
    """Require any admin role"""
    return require_role(['SUPER_ADMIN', 'VILLAGE_ADMIN', 'ACCOUNTING_ADMIN', 'MAINTENANCE_STAFF'])(f)

def require_active_user(f):
    """Require any active user"""
    return require_role(['SUPER_ADMIN', 'VILLAGE_ADMIN', 'ACCOUNTING_ADMIN', 'MAINTENANCE_STAFF', 'AUDITOR', 'RESIDENT'])(f)

