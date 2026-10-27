"""FastAPI Authentication Server."""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import timedelta

from database import get_db, init_db
from models import User
from schemas import (
    UserRegister, UserLogin, UserResponse, 
    LoginResponse, RegisterResponse, ErrorResponse
)
from auth import (
    PasswordManager, JWTTokenManager, 
    get_current_user, ACCESS_TOKEN_EXPIRE_MINUTES
)

# Initialize FastAPI app
app = FastAPI(
    title="CyberSIEM Authentication API",
    description="JWT-based authentication system for CyberSIEM (CTI-MAF)",
    version="1.0.0"
)

# ✅ CORS CONFIGURATION (PRODUCTION + DEVELOPMENT)
ALLOWED_ORIGINS = [
    # Localhost variations
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:5175",
    "http://localhost:5176",
    "http://localhost:5177",
    "http://localhost:5178",
    "http://localhost:3000",
    "http://localhost:3001",
    # 127.0.0.1 variations (PRIMARY)
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    "http://127.0.0.1:5175",
    "http://127.0.0.1:5176",
    "http://127.0.0.1:5177",
    "http://127.0.0.1:5178",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://127.0.0.1:8000",
    # Development wildcard (only for dev - remove in production)
    "http://localhost",
    "http://127.0.0.1",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Initialize database on startup
@app.on_event("startup")
def startup():
    """Initialize database on application startup."""
    init_db()


# Health check endpoint
@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "CyberSIEM Auth API"}


# Authentication Endpoints
@app.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
    responses={
        400: {"model": ErrorResponse, "description": "Email already registered or invalid data"},
        201: {"description": "User registered successfully"}
    }
)
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """
    Register a new user.
    
    - **name**: User's full name
    - **email**: User's email (must be unique)
    - **password**: User's password (minimum 8 characters)
    """
    # Check if email already exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Hash password and create user
    hashed_password = PasswordManager.hash_password(user_data.password)
    new_user = User(
        name=user_data.name,
        email=user_data.email,
        password=hashed_password
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {
        "message": "User registered successfully",
        "user": UserResponse.model_validate(new_user)
    }


@app.post(
    "/login",
    response_model=LoginResponse,
    tags=["Authentication"],
    responses={
        401: {"model": ErrorResponse, "description": "Invalid credentials"},
        200: {"description": "Login successful"}
    }
)
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    """
    Login user and return JWT token.
    
    - **email**: User's email
    - **password**: User's password
    
    Returns JWT access token and user information.
    """
    # Find user by email
    user = db.query(User).filter(User.email == credentials.email).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify password
    if not PasswordManager.verify_password(credentials.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = JWTTokenManager.create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse.model_validate(user)
    }


@app.get(
    "/profile",
    response_model=UserResponse,
    tags=["Protected"],
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        200: {"description": "User profile retrieved successfully"}
    }
)
def get_profile(payload: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Get current user profile (protected route).
    
    Requires valid JWT token in Authorization header.
    """
    email = payload.get("sub")
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse.model_validate(user)


@app.get(
    "/logout",
    tags=["Authentication"],
    responses={200: {"description": "Logout successful"}}
)
def logout():
    """
    Logout endpoint (token invalidation on client-side).
    
    Note: JWT tokens are stateless. Client should remove token from localStorage.
    """
    return {"message": "Logged out successfully"}


# Root endpoint
@app.get("/", tags=["Info"])
def root():
    """Root endpoint with API information."""
    return {
        "name": "CyberSIEM Authentication API",
        "version": "1.0.0",
        "docs": "/docs",
        "redoc": "/redoc"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)  # Changed to 8003 for stability
