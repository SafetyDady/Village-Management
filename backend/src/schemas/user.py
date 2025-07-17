from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime
from ..models.user import UserRole, UserStatus

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    email: EmailStr = Field(..., description="Email address")
    full_name: str = Field(..., min_length=2, max_length=100, description="Full name")
    phone: Optional[str] = Field(None, max_length=20, description="Phone number")
    role: UserRole = Field(default=UserRole.RESIDENT, description="User role")
    status: UserStatus = Field(default=UserStatus.PENDING, description="User status")
    address: Optional[str] = Field(None, description="Address")
    house_number: Optional[str] = Field(None, max_length=20, description="House number")
    id_card_number: Optional[str] = Field(None, max_length=20, description="ID card number")
    notes: Optional[str] = Field(None, description="Additional notes")

class UserCreate(UserBase):
    password: str = Field(..., min_length=6, max_length=100, description="Password")
    is_active: bool = Field(default=True, description="Is user active")
    is_verified: bool = Field(default=False, description="Is user verified")

class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50, description="Username")
    email: Optional[EmailStr] = Field(None, description="Email address")
    full_name: Optional[str] = Field(None, min_length=2, max_length=100, description="Full name")
    phone: Optional[str] = Field(None, max_length=20, description="Phone number")
    role: Optional[UserRole] = Field(None, description="User role")
    status: Optional[UserStatus] = Field(None, description="User status")
    address: Optional[str] = Field(None, description="Address")
    house_number: Optional[str] = Field(None, max_length=20, description="House number")
    id_card_number: Optional[str] = Field(None, max_length=20, description="ID card number")
    notes: Optional[str] = Field(None, description="Additional notes")
    is_active: Optional[bool] = Field(None, description="Is user active")
    is_verified: Optional[bool] = Field(None, description="Is user verified")
    password: Optional[str] = Field(None, min_length=6, max_length=100, description="New password")

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    phone: Optional[str]
    is_active: bool
    is_verified: bool
    role: UserRole
    status: UserStatus
    address: Optional[str]
    house_number: Optional[str]
    id_card_number: Optional[str]
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime]
    notes: Optional[str]

    class Config:
        from_attributes = True

class UserList(BaseModel):
    users: List[UserResponse]
    total: int
    page: int
    size: int
    pages: int

class UserStats(BaseModel):
    total_users: int
    active_users: int
    inactive_users: int
    pending_users: int
    by_role: dict
    by_status: dict

