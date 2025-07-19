"""
Unit Tests for AuthService
Tests password hashing, user authentication, and token generation
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
import bcrypt

from src.auth import AuthService

class TestAuthService:
    """Test cases for AuthService"""
    
    def test_hash_password(self):
        """Test password hashing"""
        password = "test_password_123"
        hashed = AuthService.hash_password(password)
        
        # Check that hash is generated
        assert hashed is not None
        assert isinstance(hashed, str)
        assert len(hashed) > 0
        
        # Check that hash is different from original password
        assert hashed != password
        
        # Check that hash starts with bcrypt prefix
        assert hashed.startswith('$2b$')
    
    def test_verify_password_correct(self):
        """Test password verification with correct password"""
        password = "test_password_123"
        hashed = AuthService.hash_password(password)
        
        # Verify correct password
        assert AuthService.verify_password(password, hashed) is True
    
    def test_verify_password_incorrect(self):
        """Test password verification with incorrect password"""
        password = "test_password_123"
        wrong_password = "wrong_password"
        hashed = AuthService.hash_password(password)
        
        # Verify incorrect password
        assert AuthService.verify_password(wrong_password, hashed) is False
    
    def test_verify_password_empty(self):
        """Test password verification with empty password"""
        password = "test_password_123"
        hashed = AuthService.hash_password(password)
        
        # Verify empty password
        assert AuthService.verify_password("", hashed) is False
    
    @patch('src.auth.get_db_connection')
    def test_get_user_by_email_found(self, mock_get_db, sample_user):
        """Test getting user by email when user exists"""
        # Setup mock
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = None
        mock_get_db.return_value = mock_conn
        
        # Mock cursor to return sample user
        mock_cursor.fetchone.return_value = sample_user
        
        # Test
        result = AuthService.get_user_by_email("test@village.com")
        
        # Assertions
        assert result is not None
        assert result['email'] == sample_user['email']
        assert result['id'] == sample_user['id']
        mock_cursor.execute.assert_called_once()
    
    @patch('src.auth.get_db_connection')
    def test_get_user_by_email_not_found(self, mock_get_db):
        """Test getting user by email when user doesn't exist"""
        # Setup mock
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = None
        mock_get_db.return_value = mock_conn
        
        # Mock cursor to return None
        mock_cursor.fetchone.return_value = None
        
        # Test
        result = AuthService.get_user_by_email("nonexistent@village.com")
        
        # Assertions
        assert result is None
        mock_cursor.execute.assert_called_once()
    
    @patch('src.auth.get_db_connection')
    def test_get_user_by_id_found(self, mock_get_db, sample_user):
        """Test getting user by ID when user exists"""
        # Setup mock
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = None
        mock_get_db.return_value = mock_conn
        
        # Mock cursor to return sample user
        mock_cursor.fetchone.return_value = sample_user
        
        # Test with numeric user_id (both int and string)
        result1 = AuthService.get_user_by_id(123)  # Integer
        result2 = AuthService.get_user_by_id("123")  # Numeric string
        
        # Assertions
        assert result1 is not None
        assert result1['id'] == sample_user['id']
        assert result1['email'] == sample_user['email']
        
        assert result2 is not None
        assert result2['id'] == sample_user['id']
        assert result2['email'] == sample_user['email']
        
        assert mock_cursor.execute.call_count == 2
    
    @patch('src.auth.get_db_connection')
    def test_create_user_success(self, mock_get_db):
        """Test successful user creation"""
        # Setup mock
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = None
        mock_get_db.return_value = mock_conn
        
        # Mock new user data
        new_user_data = {
            'id': 'new-user-id-123',
            'email': 'newuser@village.com',
            'full_name': 'New User',
            'role': 'RESIDENT',
            'is_active': True,
            'is_verified': True,
            'created_at': datetime.utcnow()
        }
        mock_cursor.fetchone.return_value = new_user_data
        
        # Test
        result = AuthService.create_user(
            email="newuser@village.com",
            password="password123",
            full_name="New User",
            role="RESIDENT"
        )
        
        # Assertions
        assert result is not None
        assert result['email'] == 'newuser@village.com'
        assert result['full_name'] == 'New User'
        assert result['role'] == 'RESIDENT'
        mock_cursor.execute.assert_called_once()
        mock_conn.commit.assert_called_once()
    
    @patch('src.auth.AuthService.get_user_by_email')
    @patch('src.auth.AuthService.verify_password')
    @patch('src.auth.get_db_connection')
    def test_authenticate_user_success(self, mock_get_db, mock_verify, mock_get_user, sample_user):
        """Test successful user authentication"""
        # Setup mocks
        mock_get_user.return_value = sample_user
        mock_verify.return_value = True
        
        # Mock database connection for last_login update
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = None
        mock_get_db.return_value = mock_conn
        
        # Test
        result = AuthService.authenticate_user("test@village.com", "password123")
        
        # Assertions
        assert result is not None
        assert result['email'] == sample_user['email']
        assert result['id'] == sample_user['id']
        mock_get_user.assert_called_once_with("test@village.com")
        mock_verify.assert_called_once()
    
    @patch('src.auth.AuthService.get_user_by_email')
    def test_authenticate_user_not_found(self, mock_get_user):
        """Test authentication when user doesn't exist"""
        mock_get_user.return_value = None
        
        result = AuthService.authenticate_user("nonexistent@village.com", "password123")
        
        assert result is None
        mock_get_user.assert_called_once_with("nonexistent@village.com")
    
    @patch('src.auth.AuthService.get_user_by_email')
    @patch('src.auth.AuthService.verify_password')
    def test_authenticate_user_wrong_password(self, mock_verify, mock_get_user, sample_user):
        """Test authentication with wrong password"""
        mock_get_user.return_value = sample_user
        mock_verify.return_value = False
        
        result = AuthService.authenticate_user("test@village.com", "wrong_password")
        
        assert result is None
        mock_get_user.assert_called_once_with("test@village.com")
        mock_verify.assert_called_once()
    
    @patch('src.auth.AuthService.get_user_by_email')
    @patch('src.auth.AuthService.verify_password')
    def test_authenticate_user_inactive(self, mock_verify, mock_get_user, sample_inactive_user):
        """Test authentication with inactive user"""
        mock_get_user.return_value = sample_inactive_user
        mock_verify.return_value = True
        
        result = AuthService.authenticate_user("inactive@village.com", "password123")
        
        assert result is None
        mock_get_user.assert_called_once_with("inactive@village.com")
        mock_verify.assert_called_once()
    
    @patch('src.auth.create_access_token')
    @patch('src.auth.create_refresh_token')
    def test_generate_tokens_success(self, mock_refresh_token, mock_access_token):
        """Test successful token generation"""
        # Setup mocks
        mock_access_token.return_value = "test_access_token"
        mock_refresh_token.return_value = "test_refresh_token"
        
        # Test
        result = AuthService.generate_tokens("test-user-id-123")
        
        # Assertions
        assert result is not None
        assert result['access_token'] == "test_access_token"
        assert result['refresh_token'] == "test_refresh_token"
        mock_access_token.assert_called_once()
        mock_refresh_token.assert_called_once()
    
    @patch('src.auth.get_jwt_identity')
    @patch('src.auth.AuthService.get_user_by_id')
    @patch('src.auth.create_access_token')
    def test_refresh_access_token_success(self, mock_create_token, mock_get_user, mock_get_identity, sample_user):
        """Test successful access token refresh"""
        # Setup mocks
        mock_get_identity.return_value = "test-user-id-123"
        mock_get_user.return_value = sample_user
        mock_create_token.return_value = "new_access_token"
        
        # Test
        result = AuthService.refresh_access_token()
        
        # Assertions
        assert result == "new_access_token"
        mock_get_identity.assert_called_once()
        mock_get_user.assert_called_once_with("test-user-id-123")
        mock_create_token.assert_called_once()
    
    @patch('src.auth.get_jwt_identity')
    def test_refresh_access_token_no_identity(self, mock_get_identity):
        """Test access token refresh with no identity"""
        mock_get_identity.return_value = None
        
        result = AuthService.refresh_access_token()
        
        assert result is None
        mock_get_identity.assert_called_once()
    
    @patch('src.auth.get_jwt_identity')
    @patch('src.auth.AuthService.get_user_by_id')
    def test_refresh_access_token_inactive_user(self, mock_get_user, mock_get_identity, sample_inactive_user):
        """Test access token refresh with inactive user"""
        mock_get_identity.return_value = "inactive-user-id-999"
        mock_get_user.return_value = sample_inactive_user
        
        result = AuthService.refresh_access_token()
        
        assert result is None
        mock_get_identity.assert_called_once()
        mock_get_user.assert_called_once_with("inactive-user-id-999")
    
    @patch('src.auth.get_db_connection')
    def test_update_user_success(self, mock_get_db):
        """Test successful user update"""
        # Setup mock
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.__enter__.return_value = mock_conn
        mock_conn.__exit__.return_value = None
        mock_get_db.return_value = mock_conn
        
        # Mock updated user data
        updated_user = {
            'id': 123,  # Use numeric ID
            'full_name': 'Updated Name',
            'phone': '0123456789',
            'updated_at': datetime.utcnow()
        }
        mock_cursor.fetchone.return_value = updated_user
        
        # Test with numeric user_id
        update_data = {
            'full_name': 'Updated Name',
            'phone': '0123456789'
        }
        result = AuthService.update_user(123, update_data)  # Use numeric ID
        
        # Assertions
        assert result is not None
        assert result['full_name'] == 'Updated Name'
        assert result['phone'] == '0123456789'
        mock_cursor.execute.assert_called_once()
        mock_conn.commit.assert_called_once()
    
    @patch('src.auth.get_db_connection')
    def test_update_user_no_fields(self, mock_get_db):
        """Test user update with no valid fields"""
        result = AuthService.update_user("test-user-id-123", {})
        
        assert result is None
        mock_get_db.assert_not_called()
    
    @patch('src.auth.get_db_connection')
    def test_update_user_invalid_fields(self, mock_get_db):
        """Test user update with invalid fields"""
        update_data = {
            'invalid_field': 'value',
            'another_invalid': 'value'
        }
        result = AuthService.update_user("test-user-id-123", update_data)
        
        assert result is None
        mock_get_db.assert_not_called()

