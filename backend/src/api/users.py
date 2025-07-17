from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from typing import List, Optional
import hashlib
import logging

from ..database import get_db
from ..models.user import User, UserRole, UserStatus
from ..schemas.user import UserCreate, UserUpdate, UserResponse, UserList, UserStats

router = APIRouter()
logger = logging.getLogger(__name__)

def hash_password(password: str) -> str:
    """Simple password hashing (use proper hashing in production)"""
    return hashlib.sha256(password.encode()).hexdigest()

@router.get("/", response_model=UserList)
async def get_users(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Number of records to return"),
    search: Optional[str] = Query(None, description="Search in username, email, or full_name"),
    role: Optional[UserRole] = Query(None, description="Filter by role"),
    status: Optional[UserStatus] = Query(None, description="Filter by status"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    db: Session = Depends(get_db)
):
    """
    Get list of users with pagination and filtering
    """
    try:
        query = db.query(User)
        
        # Apply filters
        if search:
            search_filter = f"%{search}%"
            query = query.filter(
                (User.username.ilike(search_filter)) |
                (User.email.ilike(search_filter)) |
                (User.full_name.ilike(search_filter))
            )
        
        if role:
            query = query.filter(User.role == role)
        
        if status:
            query = query.filter(User.status == status)
        
        if is_active is not None:
            query = query.filter(User.is_active == is_active)
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        users = query.offset(skip).limit(limit).all()
        
        # Calculate pages
        pages = (total + limit - 1) // limit
        
        return UserList(
            users=users,
            total=total,
            page=(skip // limit) + 1,
            size=limit,
            pages=pages
        )
    
    except Exception as e:
        logger.error(f"Error getting users: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve users")

@router.get("/stats", response_model=UserStats)
async def get_user_stats(db: Session = Depends(get_db)):
    """
    Get user statistics
    """
    try:
        total_users = db.query(User).count()
        active_users = db.query(User).filter(User.is_active == True).count()
        inactive_users = db.query(User).filter(User.is_active == False).count()
        pending_users = db.query(User).filter(User.status == UserStatus.PENDING).count()
        
        # Count by role
        role_counts = {}
        for role in UserRole:
            count = db.query(User).filter(User.role == role).count()
            role_counts[role.value] = count
        
        # Count by status
        status_counts = {}
        for status in UserStatus:
            count = db.query(User).filter(User.status == status).count()
            status_counts[status.value] = count
        
        return UserStats(
            total_users=total_users,
            active_users=active_users,
            inactive_users=inactive_users,
            pending_users=pending_users,
            by_role=role_counts,
            by_status=status_counts
        )
    
    except Exception as e:
        logger.error(f"Error getting user stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve user statistics")

@router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: int, db: Session = Depends(get_db)):
    """
    Get user by ID
    """
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve user")

@router.post("/", response_model=UserResponse)
async def create_user(user: UserCreate, db: Session = Depends(get_db)):
    """
    Create new user
    """
    try:
        # Check if username already exists
        existing_user = db.query(User).filter(User.username == user.username).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        # Check if email already exists
        existing_email = db.query(User).filter(User.email == user.email).first()
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already exists")
        
        # Create new user
        hashed_password = hash_password(user.password)
        db_user = User(
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            phone=user.phone,
            hashed_password=hashed_password,
            is_active=user.is_active,
            is_verified=user.is_verified,
            role=user.role,
            status=user.status,
            address=user.address,
            house_number=user.house_number,
            id_card_number=user.id_card_number,
            notes=user.notes
        )
        
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        logger.info(f"User created successfully: {db_user.username}")
        return db_user
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create user")

@router.put("/{user_id}", response_model=UserResponse)
async def update_user(user_id: int, user_update: UserUpdate, db: Session = Depends(get_db)):
    """
    Update user
    """
    try:
        # Get existing user
        db_user = db.query(User).filter(User.id == user_id).first()
        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Update fields
        update_data = user_update.dict(exclude_unset=True)
        
        # Handle password update
        if "password" in update_data:
            update_data["hashed_password"] = hash_password(update_data.pop("password"))
        
        # Check for username conflicts
        if "username" in update_data and update_data["username"] != db_user.username:
            existing_user = db.query(User).filter(
                and_(User.username == update_data["username"], User.id != user_id)
            ).first()
            if existing_user:
                raise HTTPException(status_code=400, detail="Username already exists")
        
        # Check for email conflicts
        if "email" in update_data and update_data["email"] != db_user.email:
            existing_email = db.query(User).filter(
                and_(User.email == update_data["email"], User.id != user_id)
            ).first()
            if existing_email:
                raise HTTPException(status_code=400, detail="Email already exists")
        
        # Apply updates
        for field, value in update_data.items():
            setattr(db_user, field, value)
        
        db.commit()
        db.refresh(db_user)
        
        logger.info(f"User updated successfully: {db_user.username}")
        return db_user
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating user {user_id}: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update user")

@router.delete("/{user_id}")
async def delete_user(user_id: int, db: Session = Depends(get_db)):
    """
    Delete user
    """
    try:
        # Get existing user
        db_user = db.query(User).filter(User.id == user_id).first()
        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Delete user
        db.delete(db_user)
        db.commit()
        
        logger.info(f"User deleted successfully: {db_user.username}")
        return {"message": "User deleted successfully"}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete user")

@router.post("/{user_id}/toggle-status")
async def toggle_user_status(user_id: int, db: Session = Depends(get_db)):
    """
    Toggle user active status
    """
    try:
        # Get existing user
        db_user = db.query(User).filter(User.id == user_id).first()
        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Toggle status
        db_user.is_active = not db_user.is_active
        db.commit()
        db.refresh(db_user)
        
        status = "activated" if db_user.is_active else "deactivated"
        logger.info(f"User {status} successfully: {db_user.username}")
        
        return {
            "message": f"User {status} successfully",
            "is_active": db_user.is_active
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling user status {user_id}: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to toggle user status")

