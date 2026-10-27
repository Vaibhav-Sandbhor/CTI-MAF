# CyberSIEM Frontend - Authentication UI

This is the React + Vite frontend for the CyberSIEM authentication system.

## Project Structure

```
src/
├── pages/
│   ├── Login.jsx          # Login page
│   ├── Register.jsx       # Registration page
│   └── Dashboard.jsx      # Protected dashboard
├── context/
│   └── AuthContext.jsx    # Authentication context & hooks
├── services/
│   └── api.js             # Axios API client
├── styles/
│   └── auth.css           # Global styles
├── App.jsx                # Main App component with routing
└── main.jsx               # Entry point
```

## Features

- **Modern UI**: Clean, responsive design with Tailwind-inspired styling
- **Form Validation**: Client-side validation for registration and login
- **Protected Routes**: Dashboard requires authentication
- **Automatic Token Injection**: JWT tokens automatically attached to API requests
- **Error Handling**: User-friendly error messages
- **Loading States**: Visual feedback during API calls
- **Logout**: Clear session and token removal

## Installation

```bash
npm install
```

## Development

```bash
npm run dev
```

The app will start at `http://localhost:5173`

## Build

```bash
npm run build
```

## Environment Configuration

The frontend expects the backend to be running at `http://localhost:8000`.

To change the API URL, edit `src/services/api.js`:

```javascript
const API = axios.create({
  baseURL: 'http://your-api-url:port',
  headers: {
    'Content-Type': 'application/json'
  }
})
```
