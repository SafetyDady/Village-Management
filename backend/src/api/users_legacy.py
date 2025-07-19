"""
Flask-based Users API with JWT Authentication and RBAC
Converted from main_original.py with proper authentication
"""
import logging
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib

from ..utils.rbac import require_super_admin, require_village_admin, require_any_admin, require_active_user
from ..auth import AuthService, get_db_connection

# Create Blueprint
users_bp = Blueprint('users', __name__, url_prefix='/api/v1/users')
logger = logging.getLogger(__name__)

def hash_password(password):
    """Hash password using SHA256 (legacy compatibility)"""
    return hashlib.sha256(password.encode()).hexdigest()

@users_bp.route('', methods=['GET'])
@require_any_admin  # Only admins can view all users
def get_users():
    """Get all users - Admin only"""
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
        
        # Log the action
        current_user_id = get_jwt_identity()
        logger.info(f"User {current_user_id} accessed users list")
        
        return jsonify({
            "users": users,
            "total": len(users)
        })
        
    except Exception as e:
        logger.error(f"Failed to get users: {e}")
        return jsonify({"error": str(e)}), 500

@users_bp.route('', methods=['POST'])
@require_village_admin  # Village admin or higher can create users
def create_user():
    """Create new user - Village Admin or higher"""
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
        
        # Log the action
        current_user_id = get_jwt_identity()
        logger.info(f"User {current_user_id} created new user: {user['username']}")
        
        return jsonify({
            "message": "User created successfully",
            "user": user
        }), 201
        
    except psycopg2.IntegrityError as e:
        return jsonify({"error": "Username or email already exists"}), 409
    except Exception as e:
        logger.error(f"Failed to create user: {e}")
        return jsonify({"error": str(e)}), 500

@users_bp.route('/<int:user_id>', methods=['GET'])
@require_active_user  # Any authenticated user can view individual user details
def get_user(user_id):
    """Get user by ID - Authenticated users only"""
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
            WHERE id = %s
        """, (user_id,))
        
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Convert datetime objects to strings
        for key, value in user.items():
            if isinstance(value, datetime):
                user[key] = value.isoformat()
        
        # Log the action
        current_user_id = get_jwt_identity()
        logger.info(f"User {current_user_id} accessed user details: {user_id}")
        
        return jsonify({"user": user})
        
    except Exception as e:
        logger.error(f"Failed to get user {user_id}: {e}")
        return jsonify({"error": str(e)}), 500

@users_bp.route('/<int:user_id>', methods=['PUT'])
@require_village_admin  # Village admin or higher can update users
def update_user(user_id):
    """Update user - Village Admin or higher"""
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
        
        # Log the action
        current_user_id = get_jwt_identity()
        logger.info(f"User {current_user_id} updated user: {user_id}")
        
        return jsonify({
            "message": "User updated successfully",
            "user": user
        })
        
    except psycopg2.IntegrityError as e:
        return jsonify({"error": "Username or email already exists"}), 409
    except Exception as e:
        logger.error(f"Failed to update user: {e}")
        return jsonify({"error": str(e)}), 500

@users_bp.route('/<int:user_id>', methods=['DELETE'])
@require_super_admin  # Only super admin can delete users
def delete_user(user_id):
    """Delete user - Super Admin only"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cur = conn.cursor()
        
        # Get user info before deletion for logging
        cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        user_info = cur.fetchone()
        
        if not user_info:
            return jsonify({"error": "User not found"}), 404
        
        # Delete user
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        
        conn.commit()
        cur.close()
        conn.close()
        
        # Log the action
        current_user_id = get_jwt_identity()
        logger.warning(f"User {current_user_id} deleted user: {user_info[0]} (ID: {user_id})")
        
        return jsonify({"message": "User deleted successfully"})
        
    except Exception as e:
        logger.error(f"Failed to delete user: {e}")
        return jsonify({"error": str(e)}), 500

@users_bp.route('/stats', methods=['GET'])
@require_any_admin  # Any admin can view stats
def get_user_stats():
    """Get user statistics - Admin only"""
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
        
        # Log the action
        current_user_id = get_jwt_identity()
        logger.info(f"User {current_user_id} accessed user statistics")
        
        return jsonify({
            "total_users": total,
            "active_users": active,
            "by_role": by_role,
            "by_status": by_status
        })
        
    except Exception as e:
        logger.error(f"Failed to get user stats: {e}")
        return jsonify({"error": str(e)}), 500

@users_bp.route('/<int:user_id>/toggle-status', methods=['POST'])
@require_village_admin  # Village admin or higher can toggle user status
def toggle_user_status(user_id):
    """Toggle user active status - Village Admin or higher"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500
            
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get current status
        cur.execute("SELECT username, is_active FROM users WHERE id = %s", (user_id,))
        user_info = cur.fetchone()
        
        if not user_info:
            return jsonify({"error": "User not found"}), 404
        
        # Toggle status
        new_status = not user_info['is_active']
        cur.execute("""
            UPDATE users 
            SET is_active = %s, updated_at = now() 
            WHERE id = %s
            RETURNING is_active
        """, (new_status, user_id))
        
        result = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        
        status_text = "activated" if result['is_active'] else "deactivated"
        
        # Log the action
        current_user_id = get_jwt_identity()
        logger.info(f"User {current_user_id} {status_text} user: {user_info['username']} (ID: {user_id})")
        
        return jsonify({
            "message": f"User {status_text} successfully",
            "is_active": result['is_active']
        })
        
    except Exception as e:
        logger.error(f"Failed to toggle user status: {e}")
        return jsonify({"error": str(e)}), 500

# Error handlers for this blueprint
@users_bp.errorhandler(401)
def unauthorized(error):
    return jsonify({"error": "Authentication required"}), 401

@users_bp.errorhandler(403)
def forbidden(error):
    return jsonify({"error": "Insufficient permissions"}), 403

@users_bp.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Resource not found"}), 404

@users_bp.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

