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
                'error': 'Invalid request',
                'message': 'Request must contain JSON data'
            }), 400
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        # Validation
        if not email or not password:
            return jsonify({
                'error': 'Missing required fields',
                'message': 'Email and password are required'
            }), 400
        
        if not validate_email(email):
            return jsonify({
                'error': 'Invalid email format',
                'message': 'Please provide a valid email address'
            }), 400
        
        # Authenticate user
        user = AuthService.authenticate_user(email, password)
        
        if not user:
            return jsonify({
                'error': 'Invalid credentials',
                'message': 'Invalid email or password'
            }), 401
        
        # Generate tokens
        tokens = AuthService.generate_tokens(user['id'])
        
        if not tokens:
            return jsonify({
                'error': 'Token generation failed',
                'message': 'Failed to generate authentication tokens'
            }), 500
        
        # Return success response
        return jsonify({
            'message': 'เข้าสู่ระบบสำเร็จ',
            'user': {
                'id': user['id'],
                'email': user['email'],
                'full_name': user['full_name'],
                'role': user['role'],
                'is_active': user['is_active']
            },
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token']
        }), 200
        
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({
            'error': 'Server error',
            'message': 'An error occurred during login'
        }), 500


@auth_bp.route('/register', methods=['POST'])
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'error': 'Invalid request',
                'message': 'Request must contain JSON data'
            }), 400
        
        # Extract and validate required fields
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        full_name = data.get('full_name', '').strip()
        
        if not all([email, password, full_name]):
            return jsonify({
                'error': 'Missing required fields',
                'message': 'Email, password, and full_name are required'
            }), 400
        
        # Validate email
        if not validate_email(email):
            return jsonify({
                'error': 'Invalid email format',
                'message': 'Please provide a valid email address'
            }), 400
        
        # Simple password validation for testing
        if len(password) < 6:
            return jsonify({
                'error': 'Password too weak',
                'message': 'Password must be at least 6 characters long'
            }), 400
        
        # Check if user already exists
        existing_user = AuthService.get_user_by_email(email)
        if existing_user:
            return jsonify({
                'error': 'User already exists',
                'message': 'User with this email already exists'
            }), 409
        
        # Create user
        new_user = AuthService.create_user(
            email=email,
            password=password,
            full_name=full_name,
            role=data.get('role', 'RESIDENT')
        )
        
        if not new_user:
            return jsonify({
                'error': 'Creation failed',
                'message': 'Failed to create user'
            }), 500
        
        # Return success response
        return jsonify({
            'message': 'ลงทะเบียนสำเร็จ',
            'user': {
                'id': new_user['id'],
                'email': new_user['email'],
                'full_name': new_user['full_name'],
                'role': new_user['role'],
                'is_active': new_user['is_active']
            }
        }), 201
        
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({
            'error': 'Server error',
            'message': 'An error occurred during registration'
        }), 500


@auth_bp.route('/me', methods=['GET'])
@require_active_user
def get_current_user(current_user=None):
    """Get current user profile"""
    try:
        if not current_user:
            return jsonify({
                'error': 'User not found',
                'message': 'User not found'
            }), 404
        
        # Return user data
        return jsonify({
            'user': {
                'id': current_user['id'],
                'email': current_user['email'],
                'full_name': current_user['full_name'],
                'role': current_user['role'],
                'is_active': current_user['is_active'],
                'is_verified': current_user['is_verified']
            }
        }), 200
        
    except Exception as e:
        print(f"Get current user error: {e}")
        return jsonify({
            'error': 'Server error',
            'message': 'An error occurred while fetching user data'
        }), 500


@auth_bp.route('/me', methods=['PATCH'])
@require_active_user
def update_current_user(current_user=None):
    """Update current user profile"""
    try:
        if not current_user:
            return jsonify({
                'error': 'User not found',
                'message': 'User not found'
            }), 404
        
        data = request.get_json()
        
        if not data:
            return jsonify({
                'error': 'Invalid request',
                'message': 'Request must contain JSON data'
            }), 400
        
        # Fields that users can update themselves
        allowed_fields = ['full_name', 'phone', 'address', 'house_number', 'notes']
        update_data = {}
        
        for field in allowed_fields:
            if field in data:
                update_data[field] = data[field]
        
        if not update_data:
            return jsonify({
                'error': 'No updates',
                'message': 'No valid fields to update'
            }), 400
        
        # Update user
        updated_user = AuthService.update_user(current_user['id'], update_data)
        
        if not updated_user:
            return jsonify({
                'error': 'Update failed',
                'message': 'Failed to update user'
            }), 500
        
        return jsonify({
            'message': 'อัปเดตข้อมูลสำเร็จ',
            'user': {
                'id': updated_user['id'],
                'email': updated_user['email'],
                'full_name': updated_user['full_name'],
                'phone': updated_user.get('phone'),
                'role': updated_user['role'],
                'is_active': updated_user['is_active'],
                'is_verified': updated_user['is_verified']
            }
        }), 200
        
    except Exception as e:
        print(f"Update current user error: {e}")
        return jsonify({
            'error': 'Server error',
            'message': 'An error occurred while updating user data'
        }), 500


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    """Refresh access token"""
    try:
        new_access_token = AuthService.refresh_access_token()
        
        if not new_access_token:
            return jsonify({
                'error': 'Token refresh failed',
                'message': 'Failed to refresh access token'
            }), 401
        
        return jsonify({
            'access_token': new_access_token
        }), 200
        
    except Exception as e:
        print(f"Token refresh error: {e}")
        return jsonify({
            'error': 'Server error',
            'message': 'An error occurred while refreshing token'
        }), 500


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """User logout endpoint"""
    # In a production system, you might want to blacklist the token
    # For now, we'll just return a success message
    return jsonify({
        'message': 'ออกจากระบบสำเร็จ'
    }), 200

