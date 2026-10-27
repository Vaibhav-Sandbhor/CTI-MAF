# CyberSIEM Authentication Backend

FastAPI-based authentication system with JWT tokens and SQLite database.

## Project Structure

```
backend/
├── main.py              # FastAPI application & endpoints
├── database.py          # Database configuration & setup
├── models.py            # SQLAlchemy models
├── schemas.py           # Pydantic schemas (request/response validation)
├── auth.py              # JWT & password hashing utilities
├── requirements.txt     # Python dependencies
└── auth.db             # SQLite database (auto-created)
```

## Features

- **SQLite Database**: Lightweight, file-based database
- **Password Hashing**: Bcrypt hashing for secure password storage
- **JWT Authentication**: Token-based API authentication
- **CORS Enabled**: Configured for frontend connection
- **API Documentation**: Auto-generated Swagger UI at `/docs`
- **Error Handling**: Comprehensive error responses
- **Protected Routes**: Dependencies for token verification

## API Endpoints

### Authentication

#### POST `/register`
Register a new user

**Request Body:**
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "securePassword123"
}
```

**Response:**
```json
{
  "message": "User registered successfully",
  "user": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "created_at": "2024-01-15T10:30:00"
  }
}
```

#### POST `/login`
Login and get JWT token

**Request Body:**
```json
{
  "email": "john@example.com",
  "password": "securePassword123"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "created_at": "2024-01-15T10:30:00"
  }
}
```

#### GET `/profile`
Get current user profile (Protected)

**Headers:**
```
Authorization: Bearer {token}
```

**Response:**
```json
{
  "id": 1,
  "name": "John Doe",
  "email": "john@example.com",
  "created_at": "2024-01-15T10:30:00"
}
```

#### GET `/logout`
Logout endpoint (clear token on client side)

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

### Health Check

#### GET `/health`
Service health check

**Response:**
```json
{
  "status": "healthy",
  "service": "CyberSIEM Auth API"
}
```

## Installation

### Prerequisites
- Python 3.8+
- pip

### Setup Steps

1. **Install Dependencies**
```bash
cd auth/backend
pip install -r requirements.txt
```

2. **Run the Server**
```bash
python main.py
```

The server will start at `http://localhost:8000`

## Development

### Access API Documentation

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Database

The SQLite database is automatically created on first run as `auth.db` in the backend directory.

### Configuration

Edit the following in `auth.py`:

```python
SECRET_KEY = "your-secret-key-change-in-production"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # Token expiry time
```

### CORS Configuration

Update `ALLOWED_ORIGINS` in `main.py` to allow specific frontend URLs:

```python
ALLOWED_ORIGINS = [
    "http://localhost:5173",  # Vite dev server
    "http://localhost:3000",  # Alternative
    "https://yourdomain.com",  # Production
]
```

## Database Schema

### users table

```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
```

## Error Handling

### Common Status Codes

- **200**: Success
- **201**: Created (registration)
- **400**: Bad request (validation error, duplicate email)
- **401**: Unauthorized (invalid credentials, expired token)
- **404**: Not found
- **500**: Server error

### Error Response Format

```json
{
  "detail": "Error message describing what went wrong"
}
```

## Security Features

1. **Password Hashing**: Bcrypt with salt
2. **JWT Tokens**: Signed with secret key
3. **Token Expiry**: 1 hour default
4. **CORS**: Configured for trusted origins only
5. **SQLAlchemy ORM**: Protection against SQL injection
6. **Email Validation**: Using Pydantic EmailStr

## Troubleshooting

### Port Already in Use
If port 8000 is already in use, run:
```bash
python -m uvicorn main:app --port 8001
```

### Database Issues
Delete `auth.db` and restart the server to reinitialize:
```bash
rm auth.db
python main.py
```

### Import Errors
Ensure all dependencies are installed:
```bash
pip install -r requirements.txt
```

## Environment Variables

You can set the following environment variables:

```bash
export SECRET_KEY="your-secret-key"
export ACCESS_TOKEN_EXPIRE_MINUTES=60
```

Or create a `.env` file:
```
SECRET_KEY=your-secret-key
ACCESS_TOKEN_EXPIRE_MINUTES=60
```

## Production Deployment

1. Change `SECRET_KEY` to a strong random value
2. Update `ALLOWED_ORIGINS` for production domains
3. Use environment variables for sensitive config
4. Deploy with Gunicorn:
```bash
pip install gunicorn
gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker
```

## Dependencies

- **fastapi**: Web framework
- **uvicorn**: ASGI server
- **sqlalchemy**: ORM
- **bcrypt**: Password hashing
- **python-jose**: JWT handling
- **pydantic**: Data validation
- **python-dotenv**: Environment variables

See `requirements.txt` for versions.

## License

Part of CyberSIEM (CTI-MAF) Project
