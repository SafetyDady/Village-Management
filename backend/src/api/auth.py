"""
Authentication API endpoints for Village Management System
"""
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from src.auth import AuthService, require_active_user
from src.models import User
import re

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    return True, "Password is valid"


@auth_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'error': 'invalid_request',
                'message': 'Request must contain JSON data'
            }), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Validation
        if not email or not password:
            return jsonify({
                'error': 'missing_credentials',
                'message': 'Email and password are required'
            }), 400
        
        if not validate_email(email):
            return jsonify({
                'error': 'invalid_email',
                'message': 'Invalid email format'
            }), 400
        
        # Authenticate user
        user = AuthService.authenticate_user(email, password)
        
        if not user:
            return jsonify({
                'error': 'invalid_credentials',
                'message': 'Invalid email or password'
            }), 401
        
        # Create tokens
        tokens = AuthService.create_tokens(user)
        
        # Return success response
        return jsonify({
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'email': user['email'],
                'full_name': user['full_name'],
                'role': user['role'],
                'status': user['status']
            },
            **tokens
        }), 200
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({
            'error': 'server_error',
            'message': 'An error occurred during login'
        }), 500


@auth_bp.route('/register', methods=['POST'])
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'error': 'invalid_request',
                'message': 'Request must contain JSON data'
            }), 400
        
        # Extract and validate required fields
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        full_name = data.get('full_name', '').strip()
        
        if not all([email, password, full_name]):
            return jsonify({
                'error': 'missing_fields',
                'message': 'Email, password, and full_name are required'
            }), 400
        
        # Validate email
        if not validate_email(email):
            return jsonify({
                'error': 'invalid_email',
                'message': 'Invalid email format'
            }), 400
        
        # Validate password
        is_valid, password_message = validate_password(password)
        if not is_valid:
            return jsonify({
                'error': 'invalid_password',
                'message': password_message
            }), 400
        
        # Check if user already exists
        existing_user = AuthService.get_user_by_email(email)
        if existing_user:
            return jsonify({
                'error': 'user_exists',
                'message': 'User with this email already exists'
            }), 409
        
        # Hash password
        hashed_password = AuthService.hash_password(password)
        
        # Prepare user data
        user_data = {
            'username': email,  # Use email as username
            'email': email,
            'full_name': full_name,
            'hashed_password': hashed_password,
            'phone': data.get('phone'),
            'role': data.get('role', 'RESIDENT'),
            'status': 'PENDING',  # New users start as PENDING
            'address': data.get('address'),
            'house_number': data.get('house_number'),
            'id_card_number': data.get('id_card_number'),
            'is_active': True,
            'is_verified': False,
            'notes': data.get('notes')
        }
        
        # Create user
        new_user = User.create(user_data)
        
        if not new_user:
            return jsonify({
                'error': 'creation_failed',
                'message': 'Failed to create user'
            }), 500
        
        # Return success response (without tokens - user needs approval)
        return jsonify({
            'message': 'Registration successful. Your account is pending approval.',
            'user': {
                'id': new_user['id'],
                'email': new_user['email'],
                'full_name': new_user['full_name'],
                'role': new_user['role'],
                'status': new_user['status']
            }
        }), 201
        
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({
            'error': 'server_error',
            'message': 'An error occurred during registration'
        }), 500


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
@require_active_user
def get_current_user():
    """Get current user profile"""
    try:
        current_user_id = get_jwt_identity()
        user = AuthService.get_user_by_id(current_user_id)
        
        if not user:
            return jsonify({
                'error': 'user_not_found',
                'message': 'User not found'
            }), 404
        
        # Remove sensitive information
        user_data = {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'full_name': user['full_name'],
            'phone': user['phone'],
            'role': user['role'],
            'status': user['status'],
            'address': user['address'],
            'house_number': user['house_number'],
            'id_card_number': user['id_card_number'],
            'is_active': user['is_active'],
            'is_verified': user['is_verified'],
            'created_at': user['created_at'].isoformat() if user['created_at'] else None,
            'updated_at': user['updated_at'].isoformat() if user['updated_at'] else None,
            'last_login': user['last_login'].isoformat() if user['last_login'] else None
        }
        
        return jsonify({
            'user': user_data
        }), 200
        
    except Exception as e:
        print(f"Get current user error: {e}")
        return jsonify({
            'error': 'server_error',
            'message': 'An error occurred while fetching user data'
        }), 500


@auth_bp.route('/me', methods=['PATCH'])
@jwt_required()
@require_active_user
def update_current_user():
    """Update current user profile"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return jsonify({
                'error': 'invalid_request',
                'message': 'Request must contain JSON data'
            }), 400
        
        # Fields that users can update themselves
        allowed_fields = ['full_name', 'phone', 'address', 'house_number']
        update_data = {}
        
        for field in allowed_fields:
            if field in data:
                update_data[field] = data[field]
        
        if not update_data:
            return jsonify({
                'error': 'no_updates',
                'message': 'No valid fields to update'
            }), 400
        
        # Update user
        updated_user = User.update(current_user_id, update_data)
        
        if not updated_user:
            return jsonify({
                'error': 'update_failed',
                'message': 'Failed to update user'
            }), 500
        
        # Remove sensitive information
        user_data = {
            'id': updated_user['id'],
            'username': updated_user['username'],
            'email': updated_user['email'],
            'full_name': updated_user['full_name'],
            'phone': updated_user['phone'],
            'role': updated_user['role'],
            'status': updated_user['status'],
            'address': updated_user['address'],
            'house_number': updated_user['house_number'],
            'id_card_number': updated_user['id_card_number'],
            'is_active': updated_user['is_active'],
            'is_verified': updated_user['is_verified'],
            'created_at': updated_user['created_at'].isoformat() if updated_user['created_at'] else None,
            'updated_at': updated_user['updated_at'].isoformat() if updated_user['updated_at'] else None,
            'last_login': updated_user['last_login'].isoformat() if updated_user['last_login'] else None
        }
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': user_data
        }), 200
        
    except Exception as e:
        print(f"Update current user error: {e}")
        return jsonify({
            'error': 'server_error',
            'message': 'An error occurred while updating user data'
        }), 500


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    """Refresh access token"""
    try:
        current_user_id = get_jwt_identity()
        user = AuthService.get_user_by_id(current_user_id)
        
        if not user or not user.get('is_active', False):
            return jsonify({
                'error': 'user_inactive',
                'message': 'User account is inactive'
            }), 401
        
        # Create new access token
        tokens = AuthService.create_tokens(user)
        
        return jsonify({
            'message': 'Token refreshed successfully',
            'access_token': tokens['access_token'],
            'token_type': tokens['token_type'],
            'expires_in': tokens['expires_in']
        }), 200
        
    except Exception as e:
        print(f"Token refresh error: {e}")
        return jsonify({
            'error': 'server_error',
            'message': 'An error occurred while refreshing token'
        }), 500


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """User logout endpoint"""
    # In a production system, you might want to blacklist the token
    # For now, we'll just return a success message
    return jsonify({
        'message': 'Logout successful'
    }), 200

