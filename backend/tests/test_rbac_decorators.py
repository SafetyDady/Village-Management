"""
Tests for RBAC (Role-Based Access Control) Decorators
Tests all 5 RBAC decorators with different user roles and scenarios
"""

import pytest
from unittest.mock import patch, MagicMock
from flask import Flask, jsonify
from flask_jwt_extended import JWTManager, create_access_token

from src.utils.rbac import (
    require_active_user,
    require_super_admin,
    require_village_admin,
    require_accounting_admin,
    require_any_admin,
    get_current_user
)

class TestRBACDecorators:
    """Test cases for RBAC decorators"""
    
    @pytest.fixture
    def app(self):
        """Create Flask app for testing"""
        app = Flask(__name__)
        app.config['JWT_SECRET_KEY'] = 'test-secret-key'
        app.config['TESTING'] = True
        jwt = JWTManager(app)
        return app
    
    @pytest.fixture
    def client(self, app):
        """Create test client"""
        return app.test_client()
    
    def create_test_endpoint(self, decorator, app):
        """Helper to create test endpoint with decorator"""
        @app.route('/test')
        @decorator
        def test_endpoint(current_user=None):
            return jsonify({
                'message': 'success',
                'user_id': current_user['id'] if current_user else None,
                'user_role': current_user['role'] if current_user else None
            })
        
        return test_endpoint
    
    @patch('src.utils.rbac.get_current_user')
    def test_require_active_user_success(self, mock_get_user, app, client, sample_user):
        """Test require_active_user with valid active user"""
        mock_get_user.return_value = sample_user
        
        with app.app_context():
            # Create test endpoint
            self.create_test_endpoint(require_active_user, app)
            
            # Create access token
            access_token = create_access_token(identity=sample_user['id'])
            
            # Make request with token
            response = client.get('/test', headers={
                'Authorization': f'Bearer {access_token}'
            })
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['message'] == 'success'
            assert data['user_id'] == sample_user['id']
            assert data['user_role'] == sample_user['role']
    
    @patch('src.utils.rbac.get_current_user')
    def test_require_active_user_not_found(self, mock_get_user, app, client):
        """Test require_active_user when user not found"""
        mock_get_user.return_value = None
        
        with app.app_context():
            self.create_test_endpoint(require_active_user, app)
            access_token = create_access_token(identity='nonexistent-user')
            
            response = client.get('/test', headers={
                'Authorization': f'Bearer {access_token}'
            })
            
            assert response.status_code == 401
            data = response.get_json()
            assert data['error'] == 'User not found'
    
    @patch('src.utils.rbac.get_current_user')
    def test_require_active_user_inactive(self, mock_get_user, app, client, sample_inactive_user):
        """Test require_active_user with inactive user"""
        mock_get_user.return_value = sample_inactive_user
        
        with app.app_context():
            self.create_test_endpoint(require_active_user, app)
            access_token = create_access_token(identity=sample_inactive_user['id'])
            
            response = client.get('/test', headers={
                'Authorization': f'Bearer {access_token}'
            })
            
            assert response.status_code == 403
            data = response.get_json()
            assert data['error'] == 'Account inactive'
    
    def test_require_active_user_no_token(self, app, client):
        """Test require_active_user without token"""
        with app.app_context():
            self.create_test_endpoint(require_active_user, app)
            
            response = client.get('/test')
            
            assert response.status_code == 401
    
    @patch('src.utils.rbac.get_current_user')
    def test_require_super_admin_success(self, mock_get_user, app, client, sample_admin_user):
        """Test require_super_admin with SUPER_ADMIN user"""
        mock_get_user.return_value = sample_admin_user
        
        with app.app_context():
            self.create_test_endpoint(require_super_admin, app)
            access_token = create_access_token(identity=sample_admin_user['id'])
            
            response = client.get('/test', headers={
                'Authorization': f'Bearer {access_token}'
            })
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['message'] == 'success'
            assert data['user_role'] == 'SUPER_ADMIN'
    
    @patch('src.utils.rbac.get_current_user')
    def test_require_super_admin_insufficient_role(self, mock_get_user, app, client, sample_user):
        """Test require_super_admin with insufficient role"""
        mock_get_user.return_value = sample_user  # RESIDENT role
        
        with app.app_context():
            self.create_test_endpoint(require_super_admin, app)
            access_token = create_access_token(identity=sample_user['id'])
            
            response = client.get('/test', headers={
                'Authorization': f'Bearer {access_token}'
            })
            
            assert response.status_code == 403
            data = response.get_json()
            assert data['error'] == 'Insufficient permissions'
    
    @patch('src.utils.rbac.get_current_user')
    def test_require_village_admin_with_super_admin(self, mock_get_user, app, client, sample_admin_user):
        """Test require_village_admin with SUPER_ADMIN (should pass)"""
        mock_get_user.return_value = sample_admin_user
        
        with app.app_context():
            self.create_test_endpoint(require_village_admin, app)
            access_token = create_access_token(identity=sample_admin_user['id'])
            
            response = client.get('/test', headers={
                'Authorization': f'Bearer {access_token}'
            })
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['message'] == 'success'
    
    @patch('src.utils.rbac.get_current_user')
    def test_require_village_admin_with_village_admin(self, mock_get_user, app, client, sample_village_admin_user):
        """Test require_village_admin with VILLAGE_ADMIN"""
        mock_get_user.return_value = sample_village_admin_user
        
        with app.app_context():
            self.create_test_endpoint(require_village_admin, app)
            access_token = create_access_token(identity=sample_village_admin_user['id'])
            
            response = client.get('/test', headers={
                'Authorization': f'Bearer {access_token}'
            })
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['message'] == 'success'
            assert data['user_role'] == 'VILLAGE_ADMIN'
    
    @patch('src.utils.rbac.get_current_user')
    def test_require_village_admin_insufficient_role(self, mock_get_user, app, client, sample_user):
        """Test require_village_admin with insufficient role"""
        mock_get_user.return_value = sample_user  # RESIDENT role
        
        with app.app_context():
            self.create_test_endpoint(require_village_admin, app)
            access_token = create_access_token(identity=sample_user['id'])
            
            response = client.get('/test', headers={
                'Authorization': f'Bearer {access_token}'
            })
            
            assert response.status_code == 403
            data = response.get_json()
            assert data['error'] == 'Insufficient permissions'
    
    @patch('src.utils.rbac.get_current_user')
    def test_require_accounting_admin_with_accounting_admin(self, mock_get_user, app, client):
        """Test require_accounting_admin with ACCOUNTING_ADMIN"""
        accounting_admin = {
            'id': 'accounting-admin-id',
            'email': 'accounting@village.com',
            'role': 'ACCOUNTING_ADMIN',
            'is_active': True
        }
        mock_get_user.return_value = accounting_admin
        
        with app.app_context():
            self.create_test_endpoint(require_accounting_admin, app)
            access_token = create_access_token(identity=accounting_admin['id'])
            
            response = client.get('/test', headers={
                'Authorization': f'Bearer {access_token}'
            })
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['message'] == 'success'
            assert data['user_role'] == 'ACCOUNTING_ADMIN'
    
    @patch('src.utils.rbac.get_current_user')
    def test_require_accounting_admin_with_super_admin(self, mock_get_user, app, client, sample_admin_user):
        """Test require_accounting_admin with SUPER_ADMIN (should pass)"""
        mock_get_user.return_value = sample_admin_user
        
        with app.app_context():
            self.create_test_endpoint(require_accounting_admin, app)
            access_token = create_access_token(identity=sample_admin_user['id'])
            
            response = client.get('/test', headers={
                'Authorization': f'Bearer {access_token}'
            })
            
            assert response.status_code == 200
    
    @patch('src.utils.rbac.get_current_user')
    def test_require_any_admin_with_maintenance_staff(self, mock_get_user, app, client):
        """Test require_any_admin with MAINTENANCE_STAFF"""
        maintenance_user = {
            'id': 'maintenance-id',
            'email': 'maintenance@village.com',
            'role': 'MAINTENANCE_STAFF',
            'is_active': True
        }
        mock_get_user.return_value = maintenance_user
        
        with app.app_context():
            self.create_test_endpoint(require_any_admin, app)
            access_token = create_access_token(identity=maintenance_user['id'])
            
            response = client.get('/test', headers={
                'Authorization': f'Bearer {access_token}'
            })
            
            assert response.status_code == 200
            data = response.get_json()
            assert data['message'] == 'success'
            assert data['user_role'] == 'MAINTENANCE_STAFF'
    
    @patch('src.utils.rbac.get_current_user')
    def test_require_any_admin_with_resident(self, mock_get_user, app, client, sample_user):
        """Test require_any_admin with RESIDENT (should fail)"""
        mock_get_user.return_value = sample_user
        
        with app.app_context():
            self.create_test_endpoint(require_any_admin, app)
            access_token = create_access_token(identity=sample_user['id'])
            
            response = client.get('/test', headers={
                'Authorization': f'Bearer {access_token}'
            })
            
            assert response.status_code == 403
            data = response.get_json()
            assert data['error'] == 'Insufficient permissions'
    
    @patch('src.utils.rbac.get_current_user')
    def test_require_any_admin_with_auditor(self, mock_get_user, app, client):
        """Test require_any_admin with AUDITOR (should fail)"""
        auditor_user = {
            'id': 'auditor-id',
            'email': 'auditor@village.com',
            'role': 'AUDITOR',
            'is_active': True
        }
        mock_get_user.return_value = auditor_user
        
        with app.app_context():
            self.create_test_endpoint(require_any_admin, app)
            access_token = create_access_token(identity=auditor_user['id'])
            
            response = client.get('/test', headers={
                'Authorization': f'Bearer {access_token}'
            })
            
            assert response.status_code == 403
            data = response.get_json()
            assert data['error'] == 'Insufficient permissions'
    
    @patch('src.utils.rbac.get_db_connection')
    def test_get_current_user_success(self, mock_get_db, sample_user):
        """Test get_current_user function success"""
        # Setup mock
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.close = MagicMock()
        mock_cursor.close = MagicMock()
        mock_get_db.return_value = mock_conn
        
        # Mock cursor to return user data as tuple
        user_tuple = (
            sample_user['id'],
            sample_user['email'],
            sample_user['full_name'],
            sample_user['role'],
            sample_user['is_active'],
            sample_user['is_verified']
        )
        mock_cursor.fetchone.return_value = user_tuple
        
        with patch('src.utils.rbac.get_jwt_identity', return_value=sample_user['id']):
            result = get_current_user()
            
            assert result is not None
            assert result['id'] == sample_user['id']
            assert result['email'] == sample_user['email']
            assert result['role'] == sample_user['role']
            mock_cursor.execute.assert_called_once()
    
    @patch('src.utils.rbac.get_db_connection')
    def test_get_current_user_not_found(self, mock_get_db):
        """Test get_current_user when user not found"""
        # Setup mock
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.close = MagicMock()
        mock_cursor.close = MagicMock()
        mock_get_db.return_value = mock_conn
        
        # Mock cursor to return None
        mock_cursor.fetchone.return_value = None
        
        with patch('src.utils.rbac.get_jwt_identity', return_value='nonexistent-id'):
            result = get_current_user()
            
            assert result is None
            mock_cursor.execute.assert_called_once()
    
    def test_get_current_user_no_identity(self):
        """Test get_current_user with no JWT identity"""
        with patch('src.utils.rbac.get_jwt_identity', return_value=None):
            result = get_current_user()
            
            assert result is None

class TestRoleHierarchy:
    """Test role hierarchy functions"""
    
    def test_role_hierarchy_levels(self):
        """Test role hierarchy levels are correct"""
        from src.utils.rbac import ROLE_HIERARCHY, has_role_level, get_user_role_level
        
        # Test hierarchy levels
        assert ROLE_HIERARCHY['SUPER_ADMIN'] == 5
        assert ROLE_HIERARCHY['VILLAGE_ADMIN'] == 4
        assert ROLE_HIERARCHY['ACCOUNTING_ADMIN'] == 3
        assert ROLE_HIERARCHY['MAINTENANCE_STAFF'] == 2
        assert ROLE_HIERARCHY['AUDITOR'] == 1
        assert ROLE_HIERARCHY['RESIDENT'] == 0
    
    def test_has_role_level(self):
        """Test has_role_level function"""
        from src.utils.rbac import has_role_level
        
        # SUPER_ADMIN should have access to all levels
        assert has_role_level('SUPER_ADMIN', 5) is True
        assert has_role_level('SUPER_ADMIN', 3) is True
        assert has_role_level('SUPER_ADMIN', 0) is True
        
        # RESIDENT should only have access to level 0
        assert has_role_level('RESIDENT', 0) is True
        assert has_role_level('RESIDENT', 1) is False
        assert has_role_level('RESIDENT', 3) is False
        
        # ACCOUNTING_ADMIN should have access to levels 0-3
        assert has_role_level('ACCOUNTING_ADMIN', 3) is True
        assert has_role_level('ACCOUNTING_ADMIN', 2) is True
        assert has_role_level('ACCOUNTING_ADMIN', 4) is False
    
    def test_get_user_role_level(self):
        """Test get_user_role_level function"""
        from src.utils.rbac import get_user_role_level
        
        assert get_user_role_level('SUPER_ADMIN') == 5
        assert get_user_role_level('VILLAGE_ADMIN') == 4
        assert get_user_role_level('ACCOUNTING_ADMIN') == 3
        assert get_user_role_level('MAINTENANCE_STAFF') == 2
        assert get_user_role_level('AUDITOR') == 1
        assert get_user_role_level('RESIDENT') == 0
        assert get_user_role_level('INVALID_ROLE') == -1

