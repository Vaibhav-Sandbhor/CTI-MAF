"""Pydantic schemas for request/response validation."""

from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional


class UserRegister(BaseModel):
    """Schema for user registration."""
    
    name: str = Field(..., min_length=2, max_length=255)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=255)

    class Config:
        json_schema_extra = {
            "example": {
                "name": "John Doe",
                "email": "john@example.com",
                "password": "securePassword123"
            }
        }


class UserLogin(BaseModel):
    """Schema for user login."""
    
    email: EmailStr
    password: str

    class Config:
        json_schema_extra = {
            "example": {
                "email": "john@example.com",
                "password": "securePassword123"
            }
        }


class UserResponse(BaseModel):
    """Schema for user response (without password)."""
    
    id: int
    name: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 1,
                "name": "John Doe",
                "email": "john@example.com",
                "created_at": "2024-01-15T10:30:00"
            }
        }


class LoginResponse(BaseModel):
    """Schema for login response with token."""
    
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "user": {
                    "id": 1,
                    "name": "John Doe",
                    "email": "john@example.com",
                    "created_at": "2024-01-15T10:30:00"
                }
            }
        }


class RegisterResponse(BaseModel):
    """Schema for registration response."""
    
    message: str
    user: UserResponse

    class Config:
        json_schema_extra = {
            "example": {
                "message": "User registered successfully",
                "user": {
                    "id": 1,
                    "name": "John Doe",
                    "email": "john@example.com",
                    "created_at": "2024-01-15T10:30:00"
                }
            }
        }


class ErrorResponse(BaseModel):
    """Schema for error responses."""
    
    detail: str

    class Config:
        json_schema_extra = {
            "example": {
                "detail": "Email already registered"
            }
        }
