/**
 * Token Storage Utilities for JWT Authentication
 * Handles secure storage and retrieval of JWT tokens
 */

const TOKEN_KEYS = {
  ACCESS_TOKEN: 'village_access_token',
  REFRESH_TOKEN: 'village_refresh_token',
  USER_DATA: 'village_user_data'
}

/**
 * Store tokens in localStorage
 * @param {string} accessToken - JWT access token
 * @param {string} refreshToken - JWT refresh token
 * @param {Object} userData - User data object
 */
export const storeTokens = (accessToken, refreshToken, userData = null) => {
  try {
    localStorage.setItem(TOKEN_KEYS.ACCESS_TOKEN, accessToken)
    localStorage.setItem(TOKEN_KEYS.REFRESH_TOKEN, refreshToken)
    
    if (userData) {
      localStorage.setItem(TOKEN_KEYS.USER_DATA, JSON.stringify(userData))
    }
  } catch (error) {
    console.error('Error storing tokens:', error)
  }
}

/**
 * Get access token from localStorage
 * @returns {string|null} Access token or null if not found
 */
export const getAccessToken = () => {
  try {
    return localStorage.getItem(TOKEN_KEYS.ACCESS_TOKEN)
  } catch (error) {
    console.error('Error getting access token:', error)
    return null
  }
}

/**
 * Get refresh token from localStorage
 * @returns {string|null} Refresh token or null if not found
 */
export const getRefreshToken = () => {
  try {
    return localStorage.getItem(TOKEN_KEYS.REFRESH_TOKEN)
  } catch (error) {
    console.error('Error getting refresh token:', error)
    return null
  }
}

/**
 * Get user data from localStorage
 * @returns {Object|null} User data object or null if not found
 */
export const getUserData = () => {
  try {
    const userData = localStorage.getItem(TOKEN_KEYS.USER_DATA)
    return userData ? JSON.parse(userData) : null
  } catch (error) {
    console.error('Error getting user data:', error)
    return null
  }
}

/**
 * Clear all tokens and user data from localStorage
 */
export const clearTokens = () => {
  try {
    localStorage.removeItem(TOKEN_KEYS.ACCESS_TOKEN)
    localStorage.removeItem(TOKEN_KEYS.REFRESH_TOKEN)
    localStorage.removeItem(TOKEN_KEYS.USER_DATA)
  } catch (error) {
    console.error('Error clearing tokens:', error)
  }
}

/**
 * Check if user is authenticated (has valid access token)
 * @returns {boolean} True if authenticated, false otherwise
 */
export const isAuthenticated = () => {
  const accessToken = getAccessToken()
  return !!accessToken
}

/**
 * Check if access token is expired
 * @returns {boolean} True if expired, false otherwise
 */
export const isTokenExpired = () => {
  const accessToken = getAccessToken()
  
  if (!accessToken) {
    return true
  }
  
  try {
    // Decode JWT token to check expiration
    const payload = JSON.parse(atob(accessToken.split('.')[1]))
    const currentTime = Math.floor(Date.now() / 1000)
    
    return payload.exp < currentTime
  } catch (error) {
    console.error('Error checking token expiration:', error)
    return true
  }
}

/**
 * Get token expiration time
 * @returns {number|null} Expiration timestamp or null if invalid
 */
export const getTokenExpiration = () => {
  const accessToken = getAccessToken()
  
  if (!accessToken) {
    return null
  }
  
  try {
    const payload = JSON.parse(atob(accessToken.split('.')[1]))
    return payload.exp * 1000 // Convert to milliseconds
  } catch (error) {
    console.error('Error getting token expiration:', error)
    return null
  }
}

/**
 * Get user role from stored user data
 * @returns {string|null} User role or null if not found
 */
export const getUserRole = () => {
  const userData = getUserData()
  return userData?.role || null
}

/**
 * Check if user has specific role
 * @param {string} requiredRole - Required role to check
 * @returns {boolean} True if user has the role, false otherwise
 */
export const hasRole = (requiredRole) => {
  const userRole = getUserRole()
  return userRole === requiredRole
}

/**
 * Check if user has any of the specified roles
 * @param {string[]} allowedRoles - Array of allowed roles
 * @returns {boolean} True if user has any of the roles, false otherwise
 */
export const hasAnyRole = (allowedRoles) => {
  const userRole = getUserRole()
  return allowedRoles.includes(userRole)
}

