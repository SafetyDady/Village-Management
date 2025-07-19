"""
Integration Tests for Authentication Endpoints
Tests all authentication API endpoints with various scenarios
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token

# Mock the main app to avoid database connections
@pytest.fixture
def mock_app():
    """Create mock Flask app with authentication endpoints"""
    app = Flask(__name__)
    app.config['JWT_SECRET_KEY'] = 'test-secret-key'
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 2592000
    app.config['TESTING'] = True
    
    jwt = JWTManager(app)
    
    # Import and register auth routes
    with patch('src.database.get_db_connection'):
        from src.api.auth import auth_bp
        app.register_blueprint(auth_bp, url_prefix='/auth')
    
    return app

@pytest.fixture
def client(mock_app):
    """Create test client"""
    return mock_app.test_client()

class TestAuthEndpoints:
    """Test cases for authentication endpoints"""
    
    @patch('src.api.auth.AuthService.authenticate_user')
    @patch('src.api.auth.AuthService.generate_tokens')
    def test_login_success(self, mock_generate_tokens, mock_authenticate, client, sample_user):
        """Test successful login"""
        # Setup mocks
        mock_authenticate.return_value = sample_user
        mock_generate_tokens.return_value = {
            'access_token': 'test_access_token',
            'refresh_token': 'test_refresh_token'
        }
        
        # Test data
        login_data = {
            'email': 'test@village.com',
            'password': 'password123'
        }
        
        # Make request
        response = client.post('/auth/login', 
                             data=json.dumps(login_data),
                             content_type='application/json')
        
        # Assertions
        assert response.status_code == 200
        data = response.get_json()
        assert data['message'] == 'เข้าสู่ระบบสำเร็จ'
        assert 'access_token' in data
        assert 'refresh_token' in data
        assert 'user' in data
        assert data['user']['email'] == sample_user['email']
        
        # Verify mocks were called
        mock_authenticate.assert_called_once_with('test@village.com', 'password123')
        mock_generate_tokens.assert_called_once_with(sample_user['id'])
    
    @patch('src.api.auth.AuthService.authenticate_user')
    def test_login_invalid_credentials(self, mock_authenticate, client):
        """Test login with invalid credentials"""
        mock_authenticate.return_value = None
        
        login_data = {
            'email': 'test@village.com',
            'password': 'wrong_password'
        }
        
        response = client.post('/auth/login',
                             data=json.dumps(login_data),
                             content_type='application/json')
        
        assert response.status_code == 401
        data = response.get_json()
        assert data['error'] == 'Invalid credentials'
        mock_authenticate.assert_called_once_with('test@village.com', 'wrong_password')
    
    def test_login_missing_email(self, client):
        """Test login with missing email"""
        login_data = {
            'password': 'password123'
        }
        
        response = client.post('/auth/login',
                             data=json.dumps(login_data),
                             content_type='application/json')
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == 'Missing required fields'
    
    def test_login_missing_password(self, client):
        """Test login with missing password"""
        login_data = {
            'email': 'test@village.com'
        }
        
        response = client.post('/auth/login',
                             data=json.dumps(login_data),
                             content_type='application/json')
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == 'Missing required fields'
    
    def test_login_invalid_email_format(self, client):
        """Test login with invalid email format"""
        login_data = {
            'email': 'invalid-email',
            'password': 'password123'
        }
        
        response = client.post('/auth/login',
                             data=json.dumps(login_data),
                             content_type='application/json')
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == 'Invalid email format'
    
    @patch('src.api.auth.AuthService.get_user_by_email')
    @patch('src.api.auth.AuthService.create_user')
    def test_register_success(self, mock_create_user, mock_get_user, client):
        """Test successful user registration"""
        # Setup mocks
        mock_get_user.return_value = None  # User doesn't exist
        new_user = {
            'id': 'new-user-id',
            'email': 'newuser@village.com',
            'full_name': 'New User',
            'role': 'RESIDENT',
            'is_active': True,
            'is_verified': True
        }
        mock_create_user.return_value = new_user
        
        # Test data
        register_data = {
            'email': 'newuser@village.com',
            'password': 'password123',
            'full_name': 'New User'
        }
        
        # Make request
        response = client.post('/auth/register',
                             data=json.dumps(register_data),
                             content_type='application/json')
        
        # Assertions
        assert response.status_code == 201
        data = response.get_json()
        assert data['message'] == 'ลงทะเบียนสำเร็จ'
        assert 'user' in data
        assert data['user']['email'] == 'newuser@village.com'
        
        # Verify mocks were called
        mock_get_user.assert_called_once_with('newuser@village.com')
        mock_create_user.assert_called_once()
    
    @patch('src.api.auth.AuthService.get_user_by_email')
    def test_register_user_exists(self, mock_get_user, client, sample_user):
        """Test registration when user already exists"""
        mock_get_user.return_value = sample_user
        
        register_data = {
            'email': 'test@village.com',
            'password': 'password123',
            'full_name': 'Test User'
        }
        
        response = client.post('/auth/register',
                             data=json.dumps(register_data),
                             content_type='application/json')
        
        assert response.status_code == 409
        data = response.get_json()
        assert data['error'] == 'User already exists'
        mock_get_user.assert_called_once_with('test@village.com')
    
    def test_register_missing_fields(self, client):
        """Test registration with missing required fields"""
        register_data = {
            'email': 'test@village.com'
            # Missing password and full_name
        }
        
        response = client.post('/auth/register',
                             data=json.dumps(register_data),
                             content_type='application/json')
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == 'Missing required fields'
    
    def test_register_weak_password(self, client):
        """Test registration with weak password"""
        register_data = {
            'email': 'test@village.com',
            'password': '123',  # Too short
            'full_name': 'Test User'
        }
        
        response = client.post('/auth/register',
                             data=json.dumps(register_data),
                             content_type='application/json')
        
        assert response.status_code == 400
        data = response.get_json()
        assert data['error'] == 'Password too weak'
    
    @patch('src.utils.rbac.get_current_user')
    def test_get_current_user_success(self, mock_get_user, client, sample_user, mock_app):
        """Test GET /auth/me with valid token"""
        mock_get_user.return_value = sample_user
        
        with mock_app.app_context():
            access_token = create_access_token(identity=sample_user['id'])
            
            response = client.get('/auth/me', headers={
                'Authorization': f'Bearer {access_token}'
            })
            
            assert response.status_code == 200
            data = response.get_json()
            assert 'user' in data
            assert data['user']['email'] == sample_user['email']
            assert data['user']['role'] == sample_user['role']
    
    def test_get_current_user_no_token(self, client):
        """Test GET /auth/me without token"""
        response = client.get('/auth/me')
        
        assert response.status_code == 401
    
    @patch('src.utils.rbac.get_current_user')
    @patch('src.api.auth.AuthService.update_user')
    def test_update_current_user_success(self, mock_update_user, mock_get_user, client, sample_user, mock_app):
        """Test PATCH /auth/me with valid data"""
        mock_get_user.return_value = sample_user
        
        updated_user = sample_user.copy()
        updated_user['full_name'] = 'Updated Name'
        updated_user['phone'] = '0123456789'
        mock_update_user.return_value = updated_user
        
        update_data = {
            'full_name': 'Updated Name',
            'phone': '0123456789'
        }
        
        with mock_app.app_context():
            access_token = create_access_token(identity=sample_user['id'])
            
            response = client.patch('/auth/me',
                                  data=json.dumps(update_data),
                                  content_type='application/json',
                                  headers={'Authorization': f'Bearer {access_token}'})
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['message'] == 'อัปเดตข้อมูลสำเร็จ'
            assert data['user']['full_name'] == 'Updated Name'
            assert data['user']['phone'] == '0123456789'
            
            mock_update_user.assert_called_once_with(sample_user['id'], update_data)
    
    @patch('src.api.auth.AuthService.refresh_access_token')
    def test_refresh_token_success(self, mock_refresh, client, mock_app):
        """Test POST /auth/refresh with valid refresh token"""
        mock_refresh.return_value = 'new_access_token'
        
        with mock_app.app_context():
            refresh_token = create_refresh_token(identity='test-user-id')
            
            response = client.post('/auth/refresh', headers={
                'Authorization': f'Bearer {refresh_token}'
            })
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['access_token'] == 'new_access_token'
            mock_refresh.assert_called_once()
    
    @patch('src.api.auth.AuthService.refresh_access_token')
    def test_refresh_token_failed(self, mock_refresh, client, mock_app):
        """Test POST /auth/refresh with invalid refresh token"""
        mock_refresh.return_value = None
        
        with mock_app.app_context():
            refresh_token = create_refresh_token(identity='invalid-user-id')
            
            response = client.post('/auth/refresh', headers={
                'Authorization': f'Bearer {refresh_token}'
            })
            
            assert response.status_code == 401
            data = response.get_json()
            assert data['error'] == 'Token refresh failed'
    
    def test_refresh_token_no_token(self, client):
        """Test POST /auth/refresh without token"""
        response = client.post('/auth/refresh')
        
        assert response.status_code == 401
    
    def test_logout_success(self, client, mock_app):
        """Test POST /auth/logout"""
        with mock_app.app_context():
            access_token = create_access_token(identity='test-user-id')
            
            response = client.post('/auth/logout', headers={
                'Authorization': f'Bearer {access_token}'
            })
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['message'] == 'ออกจากระบบสำเร็จ'
    
    def test_logout_no_token(self, client):
        """Test POST /auth/logout without token"""
        response = client.post('/auth/logout')
        
        assert response.status_code == 401

class TestPasswordHashing:
    """Test password hashing functionality"""
    
    def test_password_hashing_and_verification(self):
        """Test password hashing and verification process"""
        from src.auth import AuthService
        
        password = "test_password_123"
        
        # Test hashing
        hashed = AuthService.hash_password(password)
        assert hashed is not None
        assert isinstance(hashed, str)
        assert hashed != password
        assert hashed.startswith('$2b$')
        
        # Test verification with correct password
        assert AuthService.verify_password(password, hashed) is True
        
        # Test verification with incorrect password
        assert AuthService.verify_password("wrong_password", hashed) is False
        
        # Test verification with empty password
        assert AuthService.verify_password("", hashed) is False
    
    def test_password_hashing_consistency(self):
        """Test that same password produces different hashes (salt)"""
        from src.auth import AuthService
        
        password = "test_password_123"
        
        hash1 = AuthService.hash_password(password)
        hash2 = AuthService.hash_password(password)
        
        # Hashes should be different due to salt
        assert hash1 != hash2
        
        # But both should verify correctly
        assert AuthService.verify_password(password, hash1) is True
        assert AuthService.verify_password(password, hash2) is True

class TestTokenGeneration:
    """Test JWT token generation and validation"""
    
    @patch('src.auth.create_access_token')
    @patch('src.auth.create_refresh_token')
    def test_generate_tokens(self, mock_refresh_token, mock_access_token):
        """Test token generation"""
        from src.auth import AuthService
        
        # Setup mocks
        mock_access_token.return_value = "test_access_token"
        mock_refresh_token.return_value = "test_refresh_token"
        
        # Test
        result = AuthService.generate_tokens("test-user-id")
        
        # Assertions
        assert result is not None
        assert result['access_token'] == "test_access_token"
        assert result['refresh_token'] == "test_refresh_token"
        
        # Verify calls
        mock_access_token.assert_called_once()
        mock_refresh_token.assert_called_once()
    
    def test_token_generation_with_real_jwt(self, mock_app):
        """Test token generation with real JWT"""
        from src.auth import AuthService
        
        with mock_app.app_context():
            result = AuthService.generate_tokens("test-user-id-123")
            
            assert result is not None
            assert 'access_token' in result
            assert 'refresh_token' in result
            assert isinstance(result['access_token'], str)
            assert isinstance(result['refresh_token'], str)
            assert len(result['access_token']) > 0
            assert len(result['refresh_token']) > 0

