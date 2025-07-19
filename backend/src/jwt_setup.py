"""
JWT Setup and Configuration Module
"""

import os
from flask_jwt_extended import JWTManager
from datetime import timedelta

def setup_jwt(app):
    """
    Setup JWT configuration for Flask app
    """
    # JWT Configuration
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(
        seconds=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600))  # 1 hour default
    )
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(
        seconds=int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES', 2592000))  # 30 days default
    )
    
    # Initialize JWT Manager
    jwt = JWTManager(app)
    
    # JWT Error Handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return {
            'error': 'token_expired',
            'message': 'Token has expired'
        }, 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return {
            'error': 'invalid_token',
            'message': 'Invalid token'
        }, 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return {
            'error': 'missing_token',
            'message': 'Authorization token is required'
        }, 401
    
    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback(jwt_header, jwt_payload):
        return {
            'error': 'fresh_token_required',
            'message': 'Fresh token required'
        }, 401
    
    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return {
            'error': 'token_revoked',
            'message': 'Token has been revoked'
        }, 401
    
    return jwt

