# CyberSIEM Authentication System - Quick Start Instructions

## 📌 One-Time Setup

### Required Software
- Python 3.8+ (https://www.python.org/downloads/)
- Node.js 16+ (https://nodejs.org/)

Verify installation:
```bash
python --version
npm --version
```

## ⚡ Start the System (First Time)

### Step 1: Start Backend (Terminal 1)

```bash
# Navigate to backend
cd CyberSIEM\auth\backend

# Create virtual environment (first time only)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies (first time only)
pip install -r requirements.txt

# Run the server
python main.py
```

**Wait until you see:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

### Step 2: Start Frontend (Terminal 2)

```bash
# Navigate to frontend
cd CyberSIEM\auth\frontend

# Install dependencies (first time only)
npm install

# Start development server
npm run dev
```

**Wait until you see:**
```
➜  Local:   http://localhost:5173/
```

### Step 3: Access the Application

Open browser and go to: **http://localhost:5173**

✅ You're now running the Auth System!

## 🔄 Subsequent Runs (After First Time)

### Backend
```bash
cd CyberSIEM\auth\backend
venv\Scripts\activate  # Windows, or: source venv/bin/activate
python main.py
```

### Frontend
```bash
cd CyberSIEM\auth\frontend
npm run dev
```

## 🧪 Test the System

### 1. Register a User
- URL: http://localhost:5173/register
- Fill: Name, Email, Password
- Click: "Create Account"

### 2. Login
- URL: http://localhost:5173/login
- Fill: Email, Password
- Click: "Login"

### 3. Dashboard
- Automatically goes to dashboard after login
- Shows user profile
- Click "Logout" to exit

### 4. API Documentation
- URL: http://localhost:8000/docs
- Interactive API testing

## 🛑 Stop the Application

**Backend Terminal**: Press `CTRL+C`

**Frontend Terminal**: Press `CTRL+C`

## ⚠️ Troubleshooting

### Backend won't start?
```bash
# Reinstall dependencies
pip install -r requirements.txt

# Use different port
python -m uvicorn main:app --port 8001
```

### Frontend won't start?
```bash
# Clear cache and reinstall
npm cache clean --force
npm install
npm run dev
```

### Can't connect frontend to backend?
1. Ensure both servers are running
2. Check API URL in: `src/services/api.js`
3. Open browser console (F12) for errors

### Port already in use?
```bash
# Find what's using port 8000 (Windows)
netstat -ano | findstr :8000

# Find what's using port 5173 (Windows)
netstat -ano | findstr :5173
```

## 📊 System Architecture

```
Frontend (React)          Backend (FastAPI)      Database (SQLite)
http://localhost:5173  ←→  http://localhost:8000  ↔  auth.db
     ↓                           ↓
  Vite Dev Server        Uvicorn ASGI Server     Users Table
```

## 🔐 Key Files

**Backend**
- `main.py` - API endpoints
- `auth.py` - JWT & password hashing
- `database.py` - SQLite setup
- `models.py` - User data model
- `auth.db` - Database (auto-created)

**Frontend**
- `App.jsx` - Routing
- `pages/` - Login, Register, Dashboard
- `context/AuthContext.jsx` - State management
- `services/api.js` - API client

## 📝 API Endpoints

```
POST   /register       Register new user
POST   /login          Login & get JWT
GET    /profile        Get user profile (protected)
GET    /logout         Logout (protected)
GET    /health         Health check
GET    /docs           API documentation
```

## 🔑 User Flow

```
1. User visits http://localhost:5173
   ↓
2. User clicks "Register"
   ↓
3. Fills form and submits
   ↓
4. Backend validates and hashes password
   ↓
5. User stored in database
   ↓
6. User redirected to login
   ↓
7. User enters email & password
   ↓
8. Backend verifies and generates JWT
   ↓
9. Token stored in browser localStorage
   ↓
10. Dashboard loads with user data
    ↓
11. User can access protected routes
    ↓
12. Click logout to clear session
```

## 📦 Installed Packages

**Backend**: fastapi, uvicorn, sqlalchemy, bcrypt, pydantic, python-jose

**Frontend**: react, react-router-dom, axios, lucide-react

## 🚀 Next Steps

1. Test user registration and login
2. Explore API documentation at `/docs`
3. Customize styling in `src/styles/auth.css`
4. Add more features (password reset, etc.)
5. Deploy to production when ready

## 📞 Need Help?

1. Check terminal output for error messages
2. Open browser console (F12) for JavaScript errors
3. Visit API docs: http://localhost:8000/docs
4. Read README files in `auth/` folder

## ✅ Infrastructure Status

Expected running services:
- [ ] Backend API: http://localhost:8000
- [ ] Frontend App: http://localhost:5173
- [ ] Database: Created in `auth/backend/auth.db`

## 🔒 Security Notes

- Passwords are hashed with bcrypt
- Tokens expire after 1 hour
- CORS enabled for frontend only
- No sensitive data in console logs
- Never commit `.env` files

---

**Happy authenticating! 🎉**
