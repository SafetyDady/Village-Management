from .database import get_db_connection
from psycopg2.extras import RealDictCursor
from datetime import datetime

class User:
    def __init__(self, id=None, username=None, email=None, full_name=None, 
                 phone=None, role='RESIDENT', status='ACTIVE', address=None, 
                 house_number=None, id_card_number=None, created_at=None, updated_at=None):
        self.id = id
        self.username = username
        self.email = email
        self.full_name = full_name
        self.phone = phone
        self.role = role
        self.status = status
        self.address = address
        self.house_number = house_number
        self.id_card_number = id_card_number
        self.created_at = created_at
        self.updated_at = updated_at
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'phone': self.phone,
            'role': self.role,
            'status': self.status,
            'address': self.address,
            'house_number': self.house_number,
            'id_card_number': self.id_card_number,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    @staticmethod
    def get_all():
        """Get all users"""
        with get_db_connection() as conn:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    @staticmethod
    def get_by_id(user_id):
        """Get user by ID"""
        with get_db_connection() as conn:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    @staticmethod
    def create(user_data):
        """Create new user"""
        with get_db_connection() as conn:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            query = """
                INSERT INTO users (username, email, full_name, phone, role, status, 
                                 address, house_number, id_card_number)
                VALUES (%(username)s, %(email)s, %(full_name)s, %(phone)s, %(role)s, 
                       %(status)s, %(address)s, %(house_number)s, %(id_card_number)s)
                RETURNING *
            """
            
            cursor.execute(query, user_data)
            conn.commit()
            row = cursor.fetchone()
            return dict(row) if row else None
    
    @staticmethod
    def update(user_id, user_data):
        """Update user"""
        with get_db_connection() as conn:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            # Build dynamic update query
            set_clauses = []
            params = {'id': user_id}
            
            for key, value in user_data.items():
                if key != 'id' and value is not None:
                    set_clauses.append(f"{key} = %({key})s")
                    params[key] = value
            
            if not set_clauses:
                return None
            
            set_clauses.append("updated_at = NOW()")
            query = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = %(id)s RETURNING *"
            
            cursor.execute(query, params)
            conn.commit()
            row = cursor.fetchone()
            return dict(row) if row else None
    
    @staticmethod
    def delete(user_id):
        """Delete user"""
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    @staticmethod
    def search(search_term):
        """Search users by username, email, or full_name"""
        with get_db_connection() as conn:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            query = """
                SELECT * FROM users 
                WHERE username ILIKE %s OR email ILIKE %s OR full_name ILIKE %s
                ORDER BY created_at DESC
            """
            search_pattern = f"%{search_term}%"
            cursor.execute(query, (search_pattern, search_pattern, search_pattern))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

