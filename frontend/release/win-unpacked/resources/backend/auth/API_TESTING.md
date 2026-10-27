# CyberSIEM Authentication - API Testing Guide

This guide shows how to test all API endpoints using curl, Postman, or the built-in Swagger UI.

## 🔗 Quick Links

- **API Docs**: http://localhost:8000/docs (Interactive Swagger UI)
- **ReDoc**: http://localhost:8000/redoc
- **Backend URL**: http://localhost:8000
- **Frontend URL**: http://localhost:5173

## 1️⃣ Health Check

Verify the backend is running:

```bash
curl -X GET http://localhost:8000/health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "CyberSIEM Auth API"
}
```

## 2️⃣ Register a New User

### Request

```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "John Doe",
    "email": "john@example.com",
    "password": "SecurePassword123"
  }'
```

### Response (201 Created)

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

### Errors

**Email already registered (400)**
```json
{
  "detail": "Email already registered"
}
```

**Invalid data (422)**
```json
{
  "detail": [
    {
      "loc": ["body", "password"],
      "msg": "ensure this value has at least 8 characters",
      "type": "value_error.string.too_short"
    }
  ]
}
```

---

## 🔐 Login and Get Token

### Request

```bash
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePassword123"
  }'
```

### Response (200 OK)

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huQGV4YW1wbGUuY29tIiwiZXhwIjoxNjcwNDI1MDAwfQ.signature",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "created_at": "2024-01-15T10:30:00"
  }
}
```

### Save Token for Next Requests

```bash
# Save token in variable (Linux/macOS)
TOKEN=$(curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@example.com","password":"SecurePassword123"}' \
  | jq -r '.access_token')

echo $TOKEN
```

### Errors

**Invalid credentials (401)**
```json
{
  "detail": "Invalid email or password"
}
```

---

## 👤 Get User Profile (Protected)

Requires JWT token in Authorization header.

### Request

```bash
curl -X GET http://localhost:8000/profile \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Or using token variable:

```bash
TOKEN="your_jwt_token_here"

curl -X GET http://localhost:8000/profile \
  -H "Authorization: Bearer $TOKEN"
```

### Response (200 OK)

```json
{
  "id": 1,
  "name": "John Doe",
  "email": "john@example.com",
  "created_at": "2024-01-15T10:30:00"
}
```

### Errors

**Missing token (403)**
```json
{
  "detail": "Not authenticated"
}
```

**Invalid token (401)**
```json
{
  "detail": "Invalid authentication credentials"
}
```

---

## 🚪 Logout

Endpoint to signal logout (client-side token removal):

### Request

```bash
curl -X GET http://localhost:8000/logout \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### Response (200 OK)

```json
{
  "message": "Logged out successfully"
}
```

---

## 🔄 Complete User Flow Test

### Step 1: Register User

```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Alice Smith",
    "email": "alice@example.com",
    "password": "MySecure123"
  }'
```

### Step 2: Login

```bash
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "MySecure123"
  }'
```

Save the `access_token` from response.

### Step 3: Get Profile

```bash
curl -X GET http://localhost:8000/profile \
  -H "Authorization: Bearer PASTE_TOKEN_HERE"
```

### Step 4: Logout

```bash
curl -X GET http://localhost:8000/logout \
  -H "Authorization: Bearer PASTE_TOKEN_HERE"
```

---

## 📊 Using Postman

### Import Collection

1. Open Postman
2. Create new collection: "CyberSIEM Auth"
3. Add requests below

### Requests

**1. Health Check** (GET)
- URL: `http://localhost:8000/health`
- Headers: None

**2. Register** (POST)
- URL: `http://localhost:8000/register`
- Headers: `Content-Type: application/json`
- Body:
```json
{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "SecurePassword123"
}
```

**3. Login** (POST)
- URL: `http://localhost:8000/login`
- Headers: `Content-Type: application/json`
- Body:
```json
{
  "email": "john@example.com",
  "password": "SecurePassword123"
}
```

**4. Get Profile** (GET)
- URL: `http://localhost:8000/profile`
- Headers: `Authorization: Bearer {{access_token}}`

**5. Logout** (GET)
- URL: `http://localhost:8000/logout`
- Headers: `Authorization: Bearer {{access_token}}`

### Use Postman Variables

1. After login, copy `access_token`
2. In Postman, go to Environment variables
3. Add: `access_token = your_token_value`
4. Use `{{access_token}}` in protected endpoints

---

## 🌐 Using Swagger UI

Navigate to: **http://localhost:8000/docs**

### Features

- ✅ See all endpoints
- ✅ View request/response schemas
- ✅ Try endpoints interactively
- ✅ Download API specification

### Test in Swagger

1. Register user using `/register`
2. Copy returned `access_token`
3. Click "Authorize" button (top-right)
4. Paste token: `Bearer your_token_here`
5. Test protected endpoints

---

## 📝 Frontend Testing via API

### Test Registration API

```javascript
// In browser console
fetch('http://localhost:8000/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    name: 'Bob',
    email: 'bob@example.com',
    password: 'BobPass123'
  })
})
.then(r => r.json())
.then(data => console.log(data))
```

### Test Login API

```javascript
fetch('http://localhost:8000/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'bob@example.com',
    password: 'BobPass123'
  })
})
.then(r => r.json())
.then(data => {
  console.log(data)
  localStorage.setItem('token', data.access_token)
})
```

### Test Protected Endpoint

```javascript
fetch('http://localhost:8000/profile', {
  method: 'GET',
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('token')}`
  }
})
.then(r => r.json())
.then(data => console.log(data))
```

---

## ✅ Validation Rules

### Email
- Must be valid email format
- Must be unique
- Example: `user@example.com`

### Password
- Minimum 8 characters
- Can contain any characters
- Example: `SecurePass123!@#`

### Name
- Minimum 2 characters
- Maximum 255 characters
- Example: `John Doe`

---

## 🐛 Common Issues

### 422 Unprocessable Entity

**Cause**: Invalid request data

**Solution**: Check:
- Email format (must have @ and domain)
- Password length (min 8 chars)
- Name length (min 2 chars)
- All required fields present

### 400 Bad Request

**Cause**: Business logic error

**Example**: "Email already registered"

**Solution**: Use different email or login instead

### 401 Unauthorized

**Cause**: Invalid or missing token

**Solution**:
- Include `Authorization: Bearer TOKEN` header
- Token might be expired (get new token)
- Token must be valid JWT

### 500 Internal Server Error

**Cause**: Server error

**Solution**:
- Check backend logs
- Restart backend server
- Check database is accessible

---

## 🔐 Security Notes

- 🚫 Never share tokens publicly
- 🚫 Never hardcode credentials
- 🚫 Tokens expire after 1 hour
- 🚫 Don't send tokens in URLs
- ✅ Always use Bearer scheme
- ✅ Use HTTPS in production

---

## 📊 Token Structure

JWT tokens have 3 parts:

```
Header.Payload.Signature

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiJqb2huQGV4YW1wbGUuY29tIiwiZXhwIjoxNjcwNDI1MDAwfQ.
TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

Decode at: https://jwt.io/

---

## 🎯 Testing Checklist

- [ ] Health endpoint working
- [ ] Register new user successfully
- [ ] Cannot register with duplicate email
- [ ] Cannot register with short password
- [ ] Can login with correct credentials
- [ ] Cannot login with wrong password
- [ ] Can get profile with valid token
- [ ] Cannot get profile without token
- [ ] Cannot get profile with invalid token
- [ ] Logout returns success message

---

**API Testing Complete! ✅**
