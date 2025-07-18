import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify
from flask_cors import CORS
import database
import models

app = Flask(__name__)
CORS(app, origins="*")

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'asdf#FGSgvasgf$5$WGT')

try:
    database.init_database()
    if database.test_connection():
        print("✅ Database connection successful!")
    else:
        print("❌ Database connection failed!")
except Exception as e:
    print(f"❌ Database initialization error: {e}")

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "message": "Village Management API is running"})

@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        users = models.User.get_all()
        return jsonify({
            "success": True,
            "count": len(users),
            "data": users
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/users', methods=['POST'])
def create_user():
    try:
        data = request.get_json()
        
        # Hash password if provided
        import bcrypt
        password = data.get('password', 'password123')
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Prepare user data
        user_data = {
            'username': data['username'],
            'email': data['email'],
            'full_name': data.get('full_name', ''),
            'role': data.get('role', 'RESIDENT'),
            'hashed_password': hashed_password
        }
        
        user = models.User.create(user_data)
        if not user:
            return jsonify({"success": False, "error": "Failed to create user"}), 500
            
        return jsonify({"success": True, "user_id": user['id'], "data": user}), 201
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# GET user by id
@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user_by_id(user_id):
    try:
        user = models.User.get_by_id(user_id)
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        return jsonify({"success": True, "data": user})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# PUT update user by id
@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user_by_id(user_id):
    try:
        data = request.get_json()
        user = models.User.update(user_id, data)
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        return jsonify({"success": True, "data": user})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# DELETE user by id
@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user_by_id(user_id):
    try:
        result = models.User.delete(user_id)
        if not result:
            return jsonify({"success": False, "error": "User not found"}), 404
        return jsonify({"success": True, "message": "User deleted successfully"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)

