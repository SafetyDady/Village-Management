/**
 * Authentication API Service
 * Handles all authentication-related API calls
 */

import axios from 'axios'
import { getAccessToken, getRefreshToken, storeTokens, clearTokens } from '../utils/tokenStorage'

// API Base URL - Update this to match your backend URL
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000'

// Create axios instance
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000, // 10 seconds timeout
})

// Request interceptor to add auth token
apiClient.interceptors.request.use(
  (config) => {
    const token = getAccessToken()
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor to handle token refresh
apiClient.interceptors.response.use(
  (response) => {
    return response
  },
  async (error) => {
    const originalRequest = error.config
    
    // If error is 401 and we haven't already tried to refresh
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true
      
      try {
        const refreshToken = getRefreshToken()
        if (refreshToken) {
          const response = await refreshAccessToken(refreshToken)
          const { access_token } = response.data
          
          // Update the authorization header and retry the request
          originalRequest.headers.Authorization = `Bearer ${access_token}`
          return apiClient(originalRequest)
        }
      } catch (refreshError) {
        // Refresh failed, clear tokens and redirect to login
        clearTokens()
        window.location.href = '/login'
        return Promise.reject(refreshError)
      }
    }
    
    return Promise.reject(error)
  }
)

/**
 * Login user with email and password
 * @param {string} email - User email
 * @param {string} password - User password
 * @returns {Promise<Object>} Login response with tokens and user data
 */
export const login = async (email, password) => {
  try {
    const response = await apiClient.post('/auth/login', {
      email: email.toLowerCase().trim(),
      password
    })
    
    const { access_token, refresh_token, user } = response.data
    
    // Store tokens and user data
    storeTokens(access_token, refresh_token, user)
    
    return {
      success: true,
      data: response.data,
      user
    }
  } catch (error) {
    console.error('Login error:', error)
    
    const errorMessage = error.response?.data?.message || 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ'
    
    return {
      success: false,
      error: errorMessage,
      status: error.response?.status
    }
  }
}

/**
 * Register new user
 * @param {Object} userData - User registration data
 * @returns {Promise<Object>} Registration response
 */
export const register = async (userData) => {
  try {
    const response = await apiClient.post('/auth/register', userData)
    
    return {
      success: true,
      data: response.data,
      message: response.data.message
    }
  } catch (error) {
    console.error('Registration error:', error)
    
    const errorMessage = error.response?.data?.message || 'เกิดข้อผิดพลาดในการลงทะเบียน'
    
    return {
      success: false,
      error: errorMessage,
      status: error.response?.status
    }
  }
}

/**
 * Get current user profile
 * @returns {Promise<Object>} User profile data
 */
export const getCurrentUser = async () => {
  try {
    const response = await apiClient.get('/auth/me')
    
    return {
      success: true,
      data: response.data.user
    }
  } catch (error) {
    console.error('Get current user error:', error)
    
    return {
      success: false,
      error: error.response?.data?.message || 'ไม่สามารถดึงข้อมูลผู้ใช้ได้'
    }
  }
}

/**
 * Update current user profile
 * @param {Object} updateData - Data to update
 * @returns {Promise<Object>} Update response
 */
export const updateCurrentUser = async (updateData) => {
  try {
    const response = await apiClient.patch('/auth/me', updateData)
    
    // Update stored user data
    const userData = response.data.user
    storeTokens(getAccessToken(), getRefreshToken(), userData)
    
    return {
      success: true,
      data: userData,
      message: response.data.message
    }
  } catch (error) {
    console.error('Update user error:', error)
    
    return {
      success: false,
      error: error.response?.data?.message || 'ไม่สามารถอัปเดตข้อมูลได้'
    }
  }
}

/**
 * Refresh access token
 * @param {string} refreshToken - Refresh token
 * @returns {Promise<Object>} Refresh response
 */
export const refreshAccessToken = async (refreshToken) => {
  try {
    const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {}, {
      headers: {
        'Authorization': `Bearer ${refreshToken}`,
        'Content-Type': 'application/json'
      }
    })
    
    const { access_token } = response.data
    
    // Update stored access token
    storeTokens(access_token, refreshToken)
    
    return response
  } catch (error) {
    console.error('Token refresh error:', error)
    throw error
  }
}

/**
 * Logout user
 * @returns {Promise<Object>} Logout response
 */
export const logout = async () => {
  try {
    // Call logout endpoint
    await apiClient.post('/auth/logout')
    
    // Clear tokens regardless of API response
    clearTokens()
    
    return {
      success: true,
      message: 'ออกจากระบบสำเร็จ'
    }
  } catch (error) {
    console.error('Logout error:', error)
    
    // Clear tokens even if API call fails
    clearTokens()
    
    return {
      success: true,
      message: 'ออกจากระบบสำเร็จ'
    }
  }
}

/**
 * Check if backend API is available
 * @returns {Promise<boolean>} True if API is available
 */
export const checkApiHealth = async () => {
  try {
    const response = await axios.get(`${API_BASE_URL}/health`, {
      timeout: 5000
    })
    
    return response.status === 200
  } catch (error) {
    console.error('API health check failed:', error)
    return false
  }
}

// Export the configured axios instance for other API calls
export { apiClient }

// Export API base URL for reference
export { API_BASE_URL }

