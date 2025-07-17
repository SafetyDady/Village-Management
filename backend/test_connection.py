#!/usr/bin/env python3
"""
Test database connection script
"""
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.database import test_connection, create_tables
from src.config import settings

def main():
    print("🔍 Testing Smart Village Management Database Connection...")
    print(f"📊 Database Host: {settings.db_host}")
    print(f"📊 Database Name: {settings.db_name}")
    print(f"📊 Database User: {settings.db_user}")
    print(f"📊 Database Port: {settings.db_port}")
    print("-" * 60)
    
    # Test connection
    print("🔌 Testing database connection...")
    if test_connection():
        print("✅ Database connection successful!")
        
        # Create tables
        print("🏗️ Creating database tables...")
        if create_tables():
            print("✅ Database tables created successfully!")
            print("🎉 Database setup completed!")
            return True
        else:
            print("❌ Failed to create database tables!")
            return False
    else:
        print("❌ Database connection failed!")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

