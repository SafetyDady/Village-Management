"""
Pytest configuration and fixtures for testing
"""

import pytest
import os
import sys
from unittest.mock import patch, MagicMock

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

@pytest.fixture
def mock_db_connection():
    """Mock database connection"""
    with patch('src.database.get_db_connection') as mock_conn:
        # Create mock connection and cursor
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        
        mock_connection.cursor.return_value = mock_cursor
        mock_connection.__enter__.return_value = mock_connection
        mock_connection.__exit__.return_value = None
        
        mock_conn.return_value = mock_connection
        
        yield {
            'connection': mock_connection,
            'cursor': mock_cursor,
            'get_db_connection': mock_conn
        }

@pytest.fixture
def sample_user():
    """Sample user data for testing"""
    return {
        'id': 123,  # Use numeric ID instead of string
        'email': 'test@village.com',
        'full_name': 'Test User',
        'hashed_password': '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/VJBzxqWPy',  # 'password123'
        'role': 'RESIDENT',
        'is_active': True,
        'is_verified': True,
        'created_at': '2025-07-19T10:00:00',
        'updated_at': '2025-07-19T10:00:00',
        'last_login': None,
        'phone': None,
        'address': None,
        'house_number': None,
        'id_card_number': None,
        'notes': None
    }

@pytest.fixture
def sample_admin_user():
    """Sample admin user data for testing"""
    return {
        'id': 'admin-user-id-456',
        'email': 'admin@village.com',
        'full_name': 'Admin User',
        'hashed_password': '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/VJBzxqWPy',  # 'password123'
        'role': 'SUPER_ADMIN',
        'is_active': True,
        'is_verified': True,
        'created_at': '2025-07-19T10:00:00',
        'updated_at': '2025-07-19T10:00:00',
        'last_login': None,
        'phone': None,
        'address': None,
        'house_number': None,
        'id_card_number': None,
        'notes': None
    }

@pytest.fixture
def sample_village_admin_user():
    """Sample village admin user data for testing"""
    return {
        'id': 'village-admin-id-789',
        'email': 'village.admin@village.com',
        'full_name': 'Village Admin',
        'hashed_password': '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/VJBzxqWPy',  # 'password123'
        'role': 'VILLAGE_ADMIN',
        'is_active': True,
        'is_verified': True,
        'created_at': '2025-07-19T10:00:00',
        'updated_at': '2025-07-19T10:00:00',
        'last_login': None,
        'phone': None,
        'address': None,
        'house_number': None,
        'id_card_number': None,
        'notes': None
    }

@pytest.fixture
def sample_inactive_user():
    """Sample inactive user data for testing"""
    return {
        'id': 'inactive-user-id-999',
        'email': 'inactive@village.com',
        'full_name': 'Inactive User',
        'hashed_password': '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/VJBzxqWPy',  # 'password123'
        'role': 'RESIDENT',
        'is_active': False,
        'is_verified': True,
        'created_at': '2025-07-19T10:00:00',
        'updated_at': '2025-07-19T10:00:00',
        'last_login': None,
        'phone': None,
        'address': None,
        'house_number': None,
        'id_card_number': None,
        'notes': None
    }

@pytest.fixture
def mock_flask_app():
    """Mock Flask app for testing"""
    from flask import Flask
    from flask_jwt_extended import JWTManager
    
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'test-secret-key'
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 2592000
    app.config['TESTING'] = True
    
    jwt = JWTManager(app)
    
    return app

@pytest.fixture
def client(mock_flask_app):
    """Test client for Flask app"""
    return mock_flask_app.test_client()

@pytest.fixture
def app_context(mock_flask_app):
    """Flask app context for testing"""
    with mock_flask_app.app_context():
        yield mock_flask_app

