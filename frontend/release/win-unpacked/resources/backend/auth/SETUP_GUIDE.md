# CyberSIEM Authentication System - Complete Setup Guide

This guide covers the entire setup process for the CyberSIEM authentication system (both backend and frontend).

## 📋 System Requirements

- **Python**: 3.8 or higher
- **Node.js**: 16.0 or higher
- **npm**: 8.0 or higher
- **Git** (optional)
- **Operating System**: Windows, macOS, or Linux

## 🚀 Quick Start (Both Backend & Frontend)

### 1. Backend Setup

```bash
# Navigate to backend directory
cd CyberSIEM/auth/backend

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the server
python main.py
```

**Expected Output:**
```
INFO:     Started server process [1234]
INFO:     Uvicorn running on http://0.0.0.0:8000
```

✅ Backend is now running at `http://localhost:8000`

### 2. Frontend Setup (New Terminal/Tab)

```bash
# Navigate to frontend directory
cd CyberSIEM/auth/frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

**Expected Output:**
```
  VITE v5.0.0  ready in xxx ms

  ➜  Local:   http://localhost:5173/
```

✅ Frontend is now running at `http://localhost:5173`

## 📍 Architecture Overview

```
CyberSIEM/
│
├── auth/
│   ├── backend/
│   │   ├── main.py           (FastAPI app)
│   │   ├── database.py       (SQLite setup)
│   │   ├── models.py         (User model)
│   │   ├── schemas.py        (Validation)
│   │   ├── auth.py           (JWT & bcrypt)
│   │   ├── requirements.txt  (Dependencies)
│   │   └── auth.db           (Database)
│   │
│   └── frontend/
│       ├── src/
│       │   ├── pages/         (Login, Register, Dashboard)
│       │   ├── context/       (AuthContext)
│       │   ├── services/      (API client)
│       │   ├── styles/        (CSS)
│       │   ├── App.jsx        (Routing)
│       │   └── main.jsx       (Entry point)
│       ├── index.html
│       ├── package.json
│       └── vite.config.js
│
├── honeypot/
├── portscan_module/
├── ransomware_module/
└── (other modules)
```

## 🔐 Authentication Flow

1. **Register**: User creates account with name, email, password
2. **Hash**: Password is hashed using bcrypt
3. **Store**: User data stored in SQLite database
4. **Login**: User logs in with email & password
5. **Verify**: Password verified against hash
6. **Token**: JWT token generated and returned
7. **Store**: Token saved in localStorage
8. **Protected**: Token sent with API requests automatically
9. **Verify**: Backend validates token on protected routes
10. **Logout**: Token removed from localStorage

## 🧪 Testing the System

### 1. Health Check (Backend)

```bash
curl http://localhost:8000/health
```

Expected Response:
```json
{
  "status": "healthy",
  "service": "CyberSIEM Auth API"
}
```

### 2. API Documentation

Visit: `http://localhost:8000/docs`

This opens Swagger UI where you can test all endpoints interactively.

### 3. Full User Flow

1. **Register**
   - Go to http://localhost:5173/register
   - Enter name, email, password
   - Click "Create Account"

2. **Login**
   - Go to http://localhost:5173/login
   - Use registered email & password
   - Click "Login"

3. **Dashboard**
   - Automatically redirected after login
   - See user profile information
   - Click "Logout" to clear session

## 📝 API Endpoints Reference

### Public Endpoints

```
POST   /register              # Register new user
POST   /login                 # Login & get JWT token
GET    /health                # Health check
GET    /docs                  # Swagger documentation
GET    /redoc                 # ReDoc documentation
```

### Protected Endpoints

```
GET    /profile               # Get current user (requires JWT)
GET    /logout                # Logout (requires JWT)
```

## 🔧 Configuration

### Backend Configuration (auth/backend/auth.py)

```python
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# CORS allowed origins in main.py
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://localhost:3000",
]
```

### Frontend Configuration (auth/frontend/src/services/api.js)

```javascript
const API = axios.create({
  baseURL: 'http://localhost:8000',  // Change for production
  headers: {
    'Content-Type': 'application/json'
  }
})
```

## 🚨 Troubleshooting

### Backend Issues

**Problem**: Port 8000 already in use
```bash
# Use different port
python -m uvicorn main:app --port 8001
```

**Problem**: ModuleNotFoundError
```bash
# Reinstall dependencies
pip install -r requirements.txt
```

**Problem**: Database locked
```bash
# Delete and recreate database
rm auth.db
python main.py
```

### Frontend Issues

**Problem**: npm install fails
```bash
# Clear npm cache and try again
npm cache clean --force
npm install
```

**Problem**: Port 5173 already in use
```bash
# Vite will automatically use next available port
npm run dev
```

**Problem**: Cannot connect to backend
- Ensure backend is running at http://localhost:8000
- Check CORS configuration in backend/main.py
- Check browser console for errors (F12)

## 📦 Project Dependencies

### Backend (auth/backend/requirements.txt)
- **fastapi**: Web framework
- **uvicorn**: ASGI server
- **sqlalchemy**: Database ORM
- **bcrypt**: Password hashing
- **python-jose**: JWT handling
- **pydantic**: Data validation
- **cryptography**: Encryption support

### Frontend (auth/frontend/package.json)
- **react**: UI library
- **react-dom**: DOM rendering
- **react-router-dom**: Routing
- **axios**: HTTP client
- **lucide-react**: Icons

## 🔐 Security Best Practices

1. **Change SECRET_KEY**: Use strong, random value in production
2. **Update ALLOWED_ORIGINS**: Only allow trusted frontend URLs
3. **Use HTTPS**: In production, always use HTTPS
4. **Environment Variables**: Store secrets in .env file
5. **Access Control**: Never commit secrets to version control
6. **Token Expiry**: Set appropriate token expiration time
7. **CORS Policy**: Be restrictive with CORS origins

## 🌐 Deployment

### Backend (Python)

**Option 1: Heroku**
```bash
# Create Procfile
web: gunicorn main:app

# Deploy
git push heroku main
```

**Option 2: AWS, Azure, Google Cloud**
- Use containerization (Docker)
- Deploy as serverless function
- Or traditional VMs/App Services

**Option 3: VPS**
```bash
pip install gunicorn
gunicorn main:app --workers 4
```

### Frontend (React)

**Option 1: Vercel**
```bash
npm install -g vercel
vercel
```

**Option 2: Netlify**
```bash
npm run build
# Drag and drop dist folder to Netlify
```

**Option 3: GitHub Pages / Any Static Host**
```bash
npm run build
# Deploy dist/ folder
```

## 📊 Database Management

### View Database

```bash
# Install sqlite3
pip install sqlite3

# Open database
sqlite3 auth.db

# Common queries
SELECT * FROM users;
SELECT id, name, email, created_at FROM users;
```

### Reset Database

```bash
rm auth.db
python main.py  # Database will be recreated
```

## 🎯 Next Steps

1. **Customize UI**: Modify styles in `auth/frontend/src/styles/auth.css`
2. **Add Features**: Extend with password reset, email verification, etc.
3. **Integrate**: Connect other modules to use this auth system
4. **Deploy**: Move to production environment
5. **Monitor**: Set up logging and monitoring

## 📚 Additional Resources

- FastAPI Docs: https://fastapi.tiangolo.com/
- React Router: https://reactrouter.com/
- JWT Guide: https://jwt.io/
- SQLAlchemy: https://www.sqlalchemy.org/
- Vite Docs: https://vitejs.dev/

## ❓ FAQ

**Q: Can I use MySQL instead of SQLite?**
A: Yes, change DATABASE_URL in backend/database.py

**Q: How do I reset a user's password?**
A: Currently not implemented. Can be added in future versions.

**Q: How do I integrate this with other modules?**
A: Have other modules validate JWT tokens from this auth system

**Q: Can I use this auth for mobile apps?**
A: Yes, the API is RESTful and works with any client

**Q: Where are tokens stored?**
A: In browser localStorage (frontend). Consider httpOnly cookies for better security.

## 📞 Support

For issues or questions, check:
1. Error messages in terminal/console
2. API documentation at http://localhost:8000/docs
3. Code comments in source files

---

**CyberSIEM Authentication System v1.0.0**
Built with ❤️ for secure access management
