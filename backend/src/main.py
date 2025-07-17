import os
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins="*")

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'asdf#FGSgvasgf$5$WGT')

# Simple health check endpoint
@app.route('/health')
def health_check():
    return jsonify({
        'status': 'healthy',
        'message': 'Village Management API is running',
        'version': '1.0.0'
    }), 200

# Simple users endpoint (mock data for now)
@app.route('/api/users', methods=['GET'])
def get_users():
    mock_users = [
        {
            'id': 1,
            'username': 'superadmin',
            'email': 'admin@village.com',
            'full_name': 'Super Administrator',
            'role': 'SUPER_ADMIN',
            'status': 'ACTIVE',
            'created_at': '2024-01-01T00:00:00Z'
        },
        {
            'id': 2,
            'username': 'resident1',
            'email': 'resident1@village.com',
            'full_name': 'John Doe',
            'role': 'RESIDENT',
            'status': 'ACTIVE',
            'created_at': '2024-01-02T00:00:00Z'
        }
    ]
    
    return jsonify({
        'success': True,
        'data': mock_users,
        'count': len(mock_users)
    }), 200

@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.json
    
    # Simple validation
    if not data or 'username' not in data or 'email' not in data:
        return jsonify({
            'success': False,
            'error': 'Missing required fields: username, email'
        }), 400
    
    # Mock response
    new_user = {
        'id': 3,
        'username': data['username'],
        'email': data['email'],
        'full_name': data.get('full_name', ''),
        'role': data.get('role', 'RESIDENT'),
        'status': 'PENDING',
        'created_at': '2024-07-17T00:00:00Z'
    }
    
    return jsonify({
        'success': True,
        'data': new_user,
        'message': 'User created successfully (mock)'
    }), 201

# Root endpoint
@app.route('/')
def root():
    return jsonify({
        'message': 'Village Management API',
        'version': '1.0.0',
        'status': 'running',
        'endpoints': {
            'health': '/health',
            'users': '/api/users'
        }
    })

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

