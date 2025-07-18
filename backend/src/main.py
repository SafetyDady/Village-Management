import os
from flask import Flask, jsonify, request
from flask_cors import CORS
from .database import init_database, test_connection
from .models import User

app = Flask(__name__)
CORS(app, origins="*")

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'asdf#FGSgvasgf$5$WGT')

# Initialize database on startup
try:
    if test_connection():
        init_database()
        print("✅ Database connection successful!")
    else:
        print("❌ Database connection failed!")
except Exception as e:
    print(f"❌ Database initialization error: {e}")

# Root endpoint
@app.route('/')
def root():
    return jsonify({
        'message': 'Village Management API',
        'status': 'running',
        'version': '1.0.0',
        'endpoints': {
            'health': '/health',
            'users': '/api/users'
        }
    }), 200

# Health check endpoint
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'message': 'Village Management API is running',
        'version': '1.0.0'
    }), 200

# Get all users
@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        search_term = request.args.get('search', '')
        
        if search_term:
            users = User.search(search_term)
        else:
            users = User.get_all()
        
        return jsonify({
            'success': True,
            'data': users,
            'count': len(users)
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Get user by ID
@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    try:
        user = User.get_by_id(user_id)
        if user:
            return jsonify({
                'success': True,
                'data': user
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Create new user
@app.route('/api/users', methods=['POST'])
def create_user():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'email', 'full_name']
        for field in required_fields:
            if not data.get(field):
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400
        
        # Set defaults
        user_data = {
            'username': data['username'],
            'email': data['email'],
            'full_name': data['full_name'],
            'phone': data.get('phone'),
            'role': data.get('role', 'RESIDENT'),
            'status': data.get('status', 'ACTIVE'),
            'address': data.get('address'),
            'house_number': data.get('house_number'),
            'id_card_number': data.get('id_card_number')
        }
        
        user = User.create(user_data)
        
        if user:
            return jsonify({
                'success': True,
                'data': user,
                'message': 'User created successfully'
            }), 201
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to create user'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Update user
@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    try:
        data = request.get_json()
        
        # Remove id from data if present
        data.pop('id', None)
        
        user = User.update(user_id, data)
        
        if user:
            return jsonify({
                'success': True,
                'data': user,
                'message': 'User updated successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'User not found or no changes made'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Delete user
@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    try:
        success = User.delete(user_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'User deleted successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)

