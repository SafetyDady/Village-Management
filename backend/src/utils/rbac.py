"""
Role-Based Access Control (RBAC) Decorators
Provides decorators for protecting endpoints based on user roles
"""

from functools import wraps
from flask import jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from src.database import get_db_connection

def get_current_user():
    """
    Get current user from JWT token
    Returns user data or None if not found
    """
    try:
        current_user_id = get_jwt_identity()
        if not current_user_id:
            return None
        
        # Convert string user_id to int for database query
        try:
            user_id_int = int(current_user_id)
        except (ValueError, TypeError):
            print(f"Invalid user ID format: {current_user_id}")
            return None
            
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, email, full_name, role, is_active, is_verified
            FROM users 
            WHERE id = %s
        """, (user_id_int,))
        
        user_data = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user_data:
            return {
                'id': user_data[0],
                'email': user_data[1],
                'full_name': user_data[2],
                'role': user_data[3],
                'is_active': user_data[4],
                'is_verified': user_data[5]
            }
        
        return None
        
    except Exception as e:
        print(f"Error getting current user: {e}")
        return None

def require_active_user(f):
    """
    Decorator to require an active user (any role)
    """
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        try:
            user = get_current_user()
            
            if not user:
                return jsonify({
                    'error': 'User not found',
                    'message': 'ไม่พบข้อมูลผู้ใช้'
                }), 401
            
            if not user['is_active']:
                return jsonify({
                    'error': 'Account inactive',
                    'message': 'บัญชีผู้ใช้ถูกระงับ'
                }), 403
            
            # Pass user data to the endpoint
            return f(current_user=user, *args, **kwargs)
            
        except Exception as e:
            return jsonify({
                'error': 'Authentication error',
                'message': 'เกิดข้อผิดพลาดในการตรวจสอบสิทธิ์'
            }), 500
    
    return decorated_function

def require_super_admin(f):
    """
    Decorator to require SUPER_ADMIN role
    """
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        try:
            user = get_current_user()
            
            if not user:
                return jsonify({
                    'error': 'User not found',
                    'message': 'ไม่พบข้อมูลผู้ใช้'
                }), 401
            
            if not user['is_active']:
                return jsonify({
                    'error': 'Account inactive',
                    'message': 'บัญชีผู้ใช้ถูกระงับ'
                }), 403
            
            if user['role'] != 'SUPER_ADMIN':
                return jsonify({
                    'error': 'Insufficient permissions',
                    'message': 'ต้องมีสิทธิ์ Super Admin เท่านั้น'
                }), 403
            
            # Pass user data to the endpoint
            return f(current_user=user, *args, **kwargs)
            
        except Exception as e:
            return jsonify({
                'error': 'Authentication error',
                'message': 'เกิดข้อผิดพลาดในการตรวจสอบสิทธิ์'
            }), 500
    
    return decorated_function

def require_village_admin(f):
    """
    Decorator to require VILLAGE_ADMIN role or higher
    Allowed roles: SUPER_ADMIN, VILLAGE_ADMIN
    """
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        try:
            user = get_current_user()
            
            if not user:
                return jsonify({
                    'error': 'User not found',
                    'message': 'ไม่พบข้อมูลผู้ใช้'
                }), 401
            
            if not user['is_active']:
                return jsonify({
                    'error': 'Account inactive',
                    'message': 'บัญชีผู้ใช้ถูกระงับ'
                }), 403
            
            allowed_roles = ['SUPER_ADMIN', 'VILLAGE_ADMIN']
            if user['role'] not in allowed_roles:
                return jsonify({
                    'error': 'Insufficient permissions',
                    'message': 'ต้องมีสิทธิ์ Village Admin ขึ้นไป'
                }), 403
            
            # Pass user data to the endpoint
            return f(current_user=user, *args, **kwargs)
            
        except Exception as e:
            return jsonify({
                'error': 'Authentication error',
                'message': 'เกิดข้อผิดพลาดในการตรวจสอบสิทธิ์'
            }), 500
    
    return decorated_function

def require_accounting_admin(f):
    """
    Decorator to require ACCOUNTING_ADMIN role or higher
    Allowed roles: SUPER_ADMIN, VILLAGE_ADMIN, ACCOUNTING_ADMIN
    """
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        try:
            user = get_current_user()
            
            if not user:
                return jsonify({
                    'error': 'User not found',
                    'message': 'ไม่พบข้อมูลผู้ใช้'
                }), 401
            
            if not user['is_active']:
                return jsonify({
                    'error': 'Account inactive',
                    'message': 'บัญชีผู้ใช้ถูกระงับ'
                }), 403
            
            allowed_roles = ['SUPER_ADMIN', 'VILLAGE_ADMIN', 'ACCOUNTING_ADMIN']
            if user['role'] not in allowed_roles:
                return jsonify({
                    'error': 'Insufficient permissions',
                    'message': 'ต้องมีสิทธิ์ Accounting Admin ขึ้นไป'
                }), 403
            
            # Pass user data to the endpoint
            return f(current_user=user, *args, **kwargs)
            
        except Exception as e:
            return jsonify({
                'error': 'Authentication error',
                'message': 'เกิดข้อผิดพลาดในการตรวจสอบสิทธิ์'
            }), 500
    
    return decorated_function

def require_any_admin(f):
    """
    Decorator to require any admin role
    Allowed roles: SUPER_ADMIN, VILLAGE_ADMIN, ACCOUNTING_ADMIN, MAINTENANCE_STAFF
    """
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        try:
            user = get_current_user()
            
            if not user:
                return jsonify({
                    'error': 'User not found',
                    'message': 'ไม่พบข้อมูลผู้ใช้'
                }), 401
            
            if not user['is_active']:
                return jsonify({
                    'error': 'Account inactive',
                    'message': 'บัญชีผู้ใช้ถูกระงับ'
                }), 403
            
            admin_roles = ['SUPER_ADMIN', 'VILLAGE_ADMIN', 'ACCOUNTING_ADMIN', 'MAINTENANCE_STAFF']
            if user['role'] not in admin_roles:
                return jsonify({
                    'error': 'Insufficient permissions',
                    'message': 'ต้องมีสิทธิ์ Admin เท่านั้น'
                }), 403
            
            # Pass user data to the endpoint
            return f(current_user=user, *args, **kwargs)
            
        except Exception as e:
            return jsonify({
                'error': 'Authentication error',
                'message': 'เกิดข้อผิดพลาดในการตรวจสอบสิทธิ์'
            }), 500
    
    return decorated_function

# Role hierarchy for reference
ROLE_HIERARCHY = {
    'SUPER_ADMIN': 5,
    'VILLAGE_ADMIN': 4,
    'ACCOUNTING_ADMIN': 3,
    'MAINTENANCE_STAFF': 2,
    'AUDITOR': 1,
    'RESIDENT': 0
}

def has_role_level(user_role, required_level):
    """
    Check if user role meets the required level
    """
    user_level = ROLE_HIERARCHY.get(user_role, -1)
    return user_level >= required_level

def get_user_role_level(user_role):
    """
    Get numeric level for user role
    """
    return ROLE_HIERARCHY.get(user_role, -1)

