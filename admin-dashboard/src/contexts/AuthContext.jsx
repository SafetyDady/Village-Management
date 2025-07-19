/**
 * Authentication Context
 * Provides global authentication state management
 */

import React, { createContext, useContext, useReducer, useEffect } from 'react'
import { 
  isAuthenticated, 
  getUserData, 
  clearTokens,
  isTokenExpired 
} from '../utils/tokenStorage'
import { getCurrentUser, logout as apiLogout } from '../services/authApi'

// Auth action types
const AUTH_ACTIONS = {
  LOGIN_START: 'LOGIN_START',
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  LOGOUT: 'LOGOUT',
  SET_USER: 'SET_USER',
  SET_LOADING: 'SET_LOADING',
  CLEAR_ERROR: 'CLEAR_ERROR'
}

// Initial auth state
const initialState = {
  isAuthenticated: false,
  user: null,
  loading: true,
  error: null,
  isLoggingIn: false
}

// Auth reducer
const authReducer = (state, action) => {
  switch (action.type) {
    case AUTH_ACTIONS.LOGIN_START:
      return {
        ...state,
        isLoggingIn: true,
        error: null
      }
    
    case AUTH_ACTIONS.LOGIN_SUCCESS:
      return {
        ...state,
        isAuthenticated: true,
        user: action.payload.user,
        isLoggingIn: false,
        error: null
      }
    
    case AUTH_ACTIONS.LOGIN_FAILURE:
      return {
        ...state,
        isAuthenticated: false,
        user: null,
        isLoggingIn: false,
        error: action.payload.error
      }
    
    case AUTH_ACTIONS.LOGOUT:
      return {
        ...state,
        isAuthenticated: false,
        user: null,
        error: null
      }
    
    case AUTH_ACTIONS.SET_USER:
      return {
        ...state,
        user: action.payload.user,
        isAuthenticated: !!action.payload.user
      }
    
    case AUTH_ACTIONS.SET_LOADING:
      return {
        ...state,
        loading: action.payload.loading
      }
    
    case AUTH_ACTIONS.CLEAR_ERROR:
      return {
        ...state,
        error: null
      }
    
    default:
      return state
  }
}

// Create Auth Context
const AuthContext = createContext()

// Auth Provider Component
export const AuthProvider = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, initialState)

  // Initialize auth state on app load
  useEffect(() => {
    const initializeAuth = async () => {
      try {
        dispatch({ type: AUTH_ACTIONS.SET_LOADING, payload: { loading: true } })
        
        // Check if user is authenticated and token is not expired
        if (isAuthenticated() && !isTokenExpired()) {
          // Try to get fresh user data from API
          const result = await getCurrentUser()
          
          if (result.success) {
            dispatch({ 
              type: AUTH_ACTIONS.SET_USER, 
              payload: { user: result.data } 
            })
          } else {
            // API call failed, use stored user data if available
            const storedUser = getUserData()
            if (storedUser) {
              dispatch({ 
                type: AUTH_ACTIONS.SET_USER, 
                payload: { user: storedUser } 
              })
            } else {
              // No valid user data, clear tokens
              clearTokens()
              dispatch({ type: AUTH_ACTIONS.LOGOUT })
            }
          }
        } else {
          // Not authenticated or token expired
          clearTokens()
          dispatch({ type: AUTH_ACTIONS.LOGOUT })
        }
      } catch (error) {
        console.error('Auth initialization error:', error)
        clearTokens()
        dispatch({ type: AUTH_ACTIONS.LOGOUT })
      } finally {
        dispatch({ type: AUTH_ACTIONS.SET_LOADING, payload: { loading: false } })
      }
    }

    initializeAuth()
  }, [])

  // Login function
  const login = async (email, password) => {
    dispatch({ type: AUTH_ACTIONS.LOGIN_START })
    
    try {
      // Import login function dynamically to avoid circular dependency
      const { login: apiLogin } = await import('../services/authApi')
      const result = await apiLogin(email, password)
      
      if (result.success) {
        dispatch({ 
          type: AUTH_ACTIONS.LOGIN_SUCCESS, 
          payload: { user: result.user } 
        })
        return { success: true, user: result.user }
      } else {
        dispatch({ 
          type: AUTH_ACTIONS.LOGIN_FAILURE, 
          payload: { error: result.error } 
        })
        return { success: false, error: result.error }
      }
    } catch (error) {
      const errorMessage = 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ'
      dispatch({ 
        type: AUTH_ACTIONS.LOGIN_FAILURE, 
        payload: { error: errorMessage } 
      })
      return { success: false, error: errorMessage }
    }
  }

  // Logout function
  const logout = async () => {
    try {
      // Call API logout
      await apiLogout()
    } catch (error) {
      console.error('Logout API error:', error)
    } finally {
      // Always clear local state
      dispatch({ type: AUTH_ACTIONS.LOGOUT })
    }
  }

  // Update user data
  const updateUser = (userData) => {
    dispatch({ 
      type: AUTH_ACTIONS.SET_USER, 
      payload: { user: userData } 
    })
  }

  // Clear error
  const clearError = () => {
    dispatch({ type: AUTH_ACTIONS.CLEAR_ERROR })
  }

  // Check if user has specific role
  const hasRole = (requiredRole) => {
    return state.user?.role === requiredRole
  }

  // Check if user has any of the specified roles
  const hasAnyRole = (allowedRoles) => {
    return allowedRoles.includes(state.user?.role)
  }

  // Check if user is admin (any admin role)
  const isAdmin = () => {
    const adminRoles = ['SUPER_ADMIN', 'VILLAGE_ADMIN', 'ACCOUNTING_ADMIN', 'MAINTENANCE_STAFF']
    return hasAnyRole(adminRoles)
  }

  // Context value
  const value = {
    // State
    isAuthenticated: state.isAuthenticated,
    user: state.user,
    loading: state.loading,
    error: state.error,
    isLoggingIn: state.isLoggingIn,
    
    // Actions
    login,
    logout,
    updateUser,
    clearError,
    
    // Utilities
    hasRole,
    hasAnyRole,
    isAdmin
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

// Custom hook to use auth context
export const useAuth = () => {
  const context = useContext(AuthContext)
  
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  
  return context
}

// HOC for protected components
export const withAuth = (Component) => {
  return function AuthenticatedComponent(props) {
    const { isAuthenticated, loading } = useAuth()
    
    if (loading) {
      return (
        <div className="min-h-screen flex items-center justify-center">
          <div className="text-center">
            <div className="w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
            <p className="text-gray-600">กำลังโหลด...</p>
          </div>
        </div>
      )
    }
    
    if (!isAuthenticated) {
      return null // Will be handled by App component routing
    }
    
    return <Component {...props} />
  }
}

export default AuthContext

