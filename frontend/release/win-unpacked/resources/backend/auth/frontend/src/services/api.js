import axios from 'axios'

// Create axios instance with base URL
const API = axios.create({
  baseURL: 'http://127.0.0.1:8003',
  headers: {
    'Content-Type': 'application/json'
  }
})

// Add token to requests if it exists
API.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
}, (error) => {
  return Promise.reject(error)
})

// Handle response errors
API.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// Auth API calls
export const authAPI = {
  register: (name, email, password) =>
    API.post('/register', { name, email, password }),
  
  login: (email, password) =>
    API.post('/login', { email, password }),
  
  getProfile: () =>
    API.get('/profile'),
  
  logout: () =>
    API.get('/logout'),
  
  healthCheck: () =>
    API.get('/health')
}

export default API
