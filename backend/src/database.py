import os
import psycopg2
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager

# Database configuration from environment variables
DATABASE_URL = os.getenv('DATABASE_URL')

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = None
    try:
        conn = psycopg2.connect(DATABASE_URL)
        yield conn
    except Exception as e:
        if conn:
            conn.rollback()
        raise e
    finally:
        if conn:
            conn.close()

def init_database():
    """Initialize database tables"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                full_name VARCHAR(100) NOT NULL,
                phone VARCHAR(20),
                hashed_password VARCHAR(255) NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                is_verified BOOLEAN DEFAULT FALSE,
                role VARCHAR(20) DEFAULT 'RESIDENT',
                status VARCHAR(20) DEFAULT 'ACTIVE',
                address TEXT,
                house_number VARCHAR(20),
                id_card_number VARCHAR(20),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                last_login TIMESTAMP WITH TIME ZONE,
                notes TEXT
            )
        """)
        
        # Insert default admin user if not exists
        cursor.execute("""
            INSERT INTO users (username, email, full_name, hashed_password, role, status, is_active, is_verified)
            VALUES ('superadmin', 'admin@village.com', 'Super Administrator', '$2b$12$dummy.hash.for.Admin123!', 'SUPER_ADMIN', 'ACTIVE', TRUE, TRUE)
            ON CONFLICT (username) DO NOTHING
        """)
        
        # Insert sample resident if not exists
        cursor.execute("""
            INSERT INTO users (username, email, full_name, hashed_password, role, status, is_active, is_verified)
            VALUES ('resident1', 'resident1@village.com', 'John Doe', '$2b$12$dummy.hash.for.password123', 'RESIDENT', 'ACTIVE', TRUE, TRUE)
            ON CONFLICT (username) DO NOTHING
        """)
        
        conn.commit()
        print("Database initialized successfully!")

def test_connection():
    """Test database connection"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT version();")
            version = cursor.fetchone()[0]
            print(f"Connected to PostgreSQL: {version}")
            return True
    except Exception as e:
        print(f"Database connection failed: {e}")
        return False

