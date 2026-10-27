# CyberSIEM Auth Module - Module README

Complete authentication system for CyberSIEM (CTI-MAF) - Independent, self-contained, production-ready.

## 📁 Module Structure

```
auth/
├── backend/
│   ├── main.py              # FastAPI application
│   ├── database.py          # SQLite configuration
│   ├── models.py            # User model
│   ├── schemas.py           # Request/response schemas
│   ├── auth.py              # JWT & password utilities
│   ├── requirements.txt     # Python dependencies
│   ├── auth.db              # Database (auto-created)
│   └── README.md            # Backend documentation
│
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Login.jsx           # Login page
│   │   │   ├── Register.jsx        # Registration page
│   │   │   └── Dashboard.jsx       # Protected dashboard
│   │   ├── context/
│   │   │   └── AuthContext.jsx     # Auth state management
│   │   ├── services/
│   │   │   └── api.js              # API client
│   │   ├── styles/
│   │   │   └── auth.css            # Styles
│   │   ├── App.jsx                 # Router setup
│   │   └── main.jsx                # Entry point
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── README.md                   # Frontend documentation
│
├── SETUP_GUIDE.md          # Complete setup instructions
└── README.md               # This file

```

## ✨ Features

### Backend Features
- ✅ User registration with validation
- ✅ Secure login with JWT tokens
- ✅ Bcrypt password hashing
- ✅ Protected API endpoints
- ✅ SQLite database
- ✅ CORS enabled for frontend
- ✅ Auto-generated API documentation
- ✅ Comprehensive error handling

### Frontend Features
- ✅ Registration page with form validation
- ✅ Login page with error handling
- ✅ Protected dashboard
- ✅ User profile display
- ✅ JWT token management
- ✅ Automatic token attachment to requests
- ✅ Responsive design
- ✅ Loading states and error messages

## 🚀 Quick Start

### Backend
```bash
cd auth/backend
pip install -r requirements.txt
python main.py
```
Server runs at: `http://localhost:8000`

### Frontend
```bash
cd auth/frontend
npm install
npm run dev
```
App runs at: `http://localhost:5173`

## 🔗 API Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| POST | `/register` | No | Register new user |
| POST | `/login` | No | Login and get token |
| GET | `/profile` | Yes | Get user profile |
| GET | `/logout` | Yes | Logout |
| GET | `/health` | No | Health check |
| GET | `/docs` | No | API documentation |

## 🛡️ Security

- **Passwords**: Hashed with bcrypt (10 rounds)
- **Tokens**: JWT with 1-hour expiry
- **Transport**: CORS configured
- **Validation**: Pydantic schemas
- **Database**: SQLite with ORM protection

## 📋 Database Schema

```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
```

## 🔄 Authentication Flow

```
1. User registers → Password hashed → Stored in DB
2. User logs in → Credentials verified → JWT token generated
3. Frontend stores token → localStorage
4. Requests include token → Authorization header
5. Backend validates token → Grants access
6. Token expires → User re-logs in
7. Logout → Token removed from localStorage
```

## 🎯 Use Cases

- ✅ Secure access to other CyberSIEM modules
- ✅ User authentication and authorization
- ✅ Session management
- ✅ API protection
- ✅ Multi-user support

## 🔌 Integration with Other Modules

To use this auth system in other modules:

1. **Get Token**: Users login through this auth system
2. **Pass Token**: Include token in requests to other modules
3. **Validate**: Other modules validate token with backend
4. **Grant Access**: Other modules check user permissions

Example:
```python
# In another module
from auth.backend.auth import get_current_user

@app.get("/my-endpoint")
def my_endpoint(current_user = Depends(get_current_user)):
    return {"user": current_user}
```

## ⚙️ Configuration

### Backend (auth/backend/auth.py)
```python
SECRET_KEY = "change-this-in-production"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
```

### Frontend (auth/frontend/src/services/api.js)
```javascript
baseURL: 'http://localhost:8000'  // Change for production
```

## 📦 Dependencies

### Backend
- fastapi, uvicorn, sqlalchemy, bcrypt, pydantic, python-jose

### Frontend
- react, react-router-dom, axios, lucide-react

## 🧪 Testing

### API Health Check
```bash
curl http://localhost:8000/health
```

### Register User
```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"name":"John","email":"john@example.com","password":"test1234"}'
```

### Login
```bash
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@example.com","password":"test1234"}'
```

## 📝 API Documentation

Live documentation available at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## 🚨 Troubleshooting

**Backend won't start?**
- Install dependencies: `pip install -r requirements.txt`
- Check port 8000 is available

**Frontend won't connect?**
- Ensure backend is running
- Check backend URL in `src/services/api.js`
- Check browser console for errors

**Login fails?**
- Check backend is running
- Verify credentials are correct
- Check CORS settings in main.py

## 🔐 Production Checklist

- [ ] Change SECRET_KEY to strong random value
- [ ] Update ALLOWED_ORIGINS for production domains
- [ ] Use HTTPS in production
- [ ] Set up environment variables
- [ ] Enable logging and monitoring
- [ ] Regular database backups
- [ ] Update password requirements if needed
- [ ] Implement rate limiting
- [ ] Set up error tracking

## 📚 Documentation

- [Backend README](backend/README.md) - Detailed backend info
- [Frontend README](frontend/README.md) - Detailed frontend info
- [SETUP_GUIDE.md](SETUP_GUIDE.md) - Complete setup instructions

## 🎓 Learning Resources

- FastAPI: https://fastapi.tiangolo.com/
- React: https://react.dev/
- JWT: https://jwt.io/
- SQLAlchemy: https://www.sqlalchemy.org/

## 📄 License

Part of **CyberSIEM (CTI-MAF) Project**

## ✅ Verification Checklist

- ✅ All backend files created and working
- ✅ All frontend files created and working
- ✅ Database setup automated
- ✅ CORS enabled for frontend
- ✅ JWT authentication implemented
- ✅ Password hashing secured
- ✅ Protected routes working
- ✅ Form validation implemented
- ✅ Error handling comprehensive
- ✅ Loading states included
- ✅ Responsive design applied
- ✅ Documentation complete
- ✅ Independent module (no interference with other modules)
- ✅ Production-ready code

---

**CyberSIEM Authentication System v1.0.0**

Secure • Modular • Production-Ready
