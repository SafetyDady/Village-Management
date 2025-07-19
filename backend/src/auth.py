"""
Authentication Service Module
Handles JWT authentication, password hashing, and user management
"""

import bcrypt
from datetime import datetime, timedelta
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity
from src.database import get_db_connection
import psycopg2.extras

# Import RBAC decorators from utils
from src.utils.rbac import (
    require_active_user,
    require_super_admin,
    require_village_admin,
    require_accounting_admin,
    require_any_admin,
    get_current_user
)

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
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            print(f"Error getting user by email: {e}")
            return None
    
    @staticmethod
    def get_user_by_id(user_id) -> dict:
        """Get user by ID (accepts both string and int)"""
        try:
            # Convert to int for database query
            user_id_int = int(user_id) if isinstance(user_id, str) else user_id
            
            with get_db_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cursor.execute("SELECT * FROM users WHERE id = %s", (user_id_int,))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            print(f"Error getting user by ID: {e}")
            return None
    
    @staticmethod
    def create_user(email: str, password: str, full_name: str, role: str = 'RESIDENT') -> dict:
        """Create new user"""
        try:
            hashed_password = AuthService.hash_password(password)
            
            with get_db_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                
                cursor.execute("""
                    INSERT INTO users (email, hashed_password, full_name, role, is_active, is_verified, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING *
                """, (
                    email.lower().strip(),
                    hashed_password,
                    full_name.strip(),
                    role,
                    True,  # is_active
                    True,  # is_verified
                    datetime.utcnow()
                ))
                
                new_user = cursor.fetchone()
                conn.commit()
                
                return dict(new_user) if new_user else None
                
        except Exception as e:
            print(f"Error creating user: {e}")
            return None
    
    @staticmethod
    def authenticate_user(email: str, password: str) -> dict:
        """Authenticate user with email and password"""
        try:
            user = AuthService.get_user_by_email(email)
            
            if not user:
                return None
            
            if not AuthService.verify_password(password, user['hashed_password']):
                return None
            
            if not user['is_active']:
                return None
            
            # Update last login
            try:
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "UPDATE users SET last_login = %s WHERE id = %s",
                        (datetime.utcnow(), user['id'])
                    )
                    conn.commit()
            except Exception as e:
                print(f"Error updating last login: {e}")
            
            return user
            
        except Exception as e:
            print(f"Error authenticating user: {e}")
            return None
    
    @staticmethod
    def generate_tokens(user_id) -> dict:
        """Generate JWT access and refresh tokens"""
        try:
            # Ensure user_id is string for JWT subject claim
            user_id_str = str(user_id)
            
            access_token = create_access_token(
                identity=user_id_str,
                expires_delta=timedelta(hours=1)
            )
            
            refresh_token = create_refresh_token(
                identity=user_id_str,
                expires_delta=timedelta(days=30)
            )
            
            return {
                'access_token': access_token,
                'refresh_token': refresh_token
            }
            
        except Exception as e:
            print(f"Error generating tokens: {e}")
            return None
    
    @staticmethod
    def refresh_access_token() -> str:
        """Generate new access token from refresh token"""
        try:
            current_user_id = get_jwt_identity()
            
            if not current_user_id:
                return None
            
            # Verify user still exists and is active
            user = AuthService.get_user_by_id(current_user_id)
            if not user or not user['is_active']:
                return None
            
            new_access_token = create_access_token(
                identity=current_user_id,
                expires_delta=timedelta(hours=1)
            )
            
            return new_access_token
            
        except Exception as e:
            print(f"Error refreshing access token: {e}")
            return None
    
    @staticmethod
    def update_user(user_id, update_data: dict) -> dict:
        """Update user data (accepts both string and int for user_id)"""
        try:
            # Convert to int for database query
            user_id_int = int(user_id) if isinstance(user_id, str) else user_id
            
            # Build dynamic update query
            allowed_fields = ['full_name', 'phone', 'address', 'house_number', 'notes']
            update_fields = []
            update_values = []
            
            for field, value in update_data.items():
                if field in allowed_fields and value is not None:
                    update_fields.append(f"{field} = %s")
                    update_values.append(value)
            
            if not update_fields:
                return None
            
            # Add updated_at
            update_fields.append("updated_at = %s")
            update_values.append(datetime.utcnow())
            update_values.append(user_id_int)
            
            with get_db_connection() as conn:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                
                query = f"""
                    UPDATE users 
                    SET {', '.join(update_fields)}
                    WHERE id = %s
                    RETURNING *
                """
                
                cursor.execute(query, update_values)
                updated_user = cursor.fetchone()
                conn.commit()
                
                return dict(updated_user) if updated_user else None
                
        except Exception as e:
            print(f"Error updating user: {e}")
            return None

# Export RBAC decorators for backward compatibility
__all__ = [
    'AuthService',
    'require_active_user',
    'require_super_admin', 
    'require_village_admin',
    'require_accounting_admin',
    'require_any_admin',
    'get_current_user'
]

