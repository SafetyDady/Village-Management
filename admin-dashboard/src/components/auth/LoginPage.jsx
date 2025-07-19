import React, { useState, useEffect } from 'react'
import { Button } from '../ui/button.jsx'
import { Input } from '../ui/input.jsx'
import { Label } from '../ui/label.jsx'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card.jsx'
import { Home, User, Lock, Eye, EyeOff, AlertCircle, CheckCircle, Wifi, WifiOff } from 'lucide-react'
import { useAuth } from '../../contexts/AuthContext'
import { checkApiHealth } from '../../services/authApi'
import '../../styles/App.css'

function LoginPage() {
  const { login, isLoggingIn, error, clearError } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [apiStatus, setApiStatus] = useState('checking') // 'checking', 'online', 'offline'
  const [loginError, setLoginError] = useState('')

  // Check API health on component mount
  useEffect(() => {
    const checkApi = async () => {
      const isOnline = await checkApiHealth()
      setApiStatus(isOnline ? 'online' : 'offline')
    }
    
    checkApi()
    
    // Check API health every 30 seconds
    const interval = setInterval(checkApi, 30000)
    return () => clearInterval(interval)
  }, [])

  // Clear errors when user starts typing
  useEffect(() => {
    if (error || loginError) {
      const timer = setTimeout(() => {
        clearError()
        setLoginError('')
      }, 5000)
      
      return () => clearTimeout(timer)
    }
  }, [error, loginError, clearError])

  const handleLogin = async (e) => {
    e.preventDefault()
    setLoginError('')
    
    // Basic validation
    if (!email.trim()) {
      setLoginError('กรุณากรอกอีเมล')
      return
    }
    
    if (!password.trim()) {
      setLoginError('กรุณากรอกรหัสผ่าน')
      return
    }
    
    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(email.trim())) {
      setLoginError('รูปแบบอีเมลไม่ถูกต้อง')
      return
    }
    
    try {
      const result = await login(email.trim(), password)
      
      if (!result.success) {
        setLoginError(result.error || 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ')
      }
      // If successful, the AuthContext will handle the state change
    } catch (err) {
      console.error('Login error:', err)
      setLoginError('เกิดข้อผิดพลาดในการเชื่อมต่อ')
    }
  }

  const getApiStatusIcon = () => {
    switch (apiStatus) {
      case 'online':
        return <Wifi className="w-4 h-4 text-green-500" />
      case 'offline':
        return <WifiOff className="w-4 h-4 text-red-500" />
      default:
        return <div className="w-4 h-4 border-2 border-gray-400 border-t-transparent rounded-full animate-spin" />
    }
  }

  const getApiStatusText = () => {
    switch (apiStatus) {
      case 'online':
        return 'เชื่อมต่อเซิร์ฟเวอร์แล้ว'
      case 'offline':
        return 'ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้'
      default:
        return 'กำลังตรวจสอบการเชื่อมต่อ...'
    }
  }

  const displayError = error || loginError

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <Card className="shadow-2xl border-0 bg-white/80 backdrop-blur-sm">
          <CardHeader className="text-center space-y-4 pb-8">
            <div className="mx-auto w-16 h-16 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center shadow-lg">
              <Home className="w-8 h-8 text-white" />
            </div>
            <div>
              <CardTitle className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                Village Management
              </CardTitle>
              <CardDescription className="text-gray-600 mt-2">
                ระบบจัดการหมู่บ้านอัจฉริยะ v2.0
              </CardDescription>
            </div>
            
            {/* API Status Indicator */}
            <div className={`flex items-center justify-center gap-2 text-sm px-3 py-2 rounded-full ${
              apiStatus === 'online' ? 'bg-green-50 text-green-700' :
              apiStatus === 'offline' ? 'bg-red-50 text-red-700' :
              'bg-gray-50 text-gray-700'
            }`}>
              {getApiStatusIcon()}
              <span>{getApiStatusText()}</span>
            </div>
          </CardHeader>
          
          <CardContent className="space-y-6">
            {/* Error Display */}
            {displayError && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-red-800 text-sm font-medium">เกิดข้อผิดพลาด</p>
                  <p className="text-red-700 text-sm mt-1">{displayError}</p>
                </div>
              </div>
            )}
            
            <form onSubmit={handleLogin} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email" className="text-sm font-medium text-gray-700 flex items-center gap-2">
                  <User className="w-4 h-4 text-green-500" />
                  อีเมล
                </Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="กรอกอีเมล เช่น admin@village.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="h-12 border-2 border-blue-100 focus:border-blue-400 rounded-lg transition-colors"
                  required
                  disabled={isLoggingIn || apiStatus === 'offline'}
                />
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="password" className="text-sm font-medium text-gray-700 flex items-center gap-2">
                  <Lock className="w-4 h-4 text-orange-500" />
                  รหัสผ่าน
                </Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="กรอกรหัสผ่าน"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="h-12 border-2 border-purple-100 focus:border-purple-400 rounded-lg pr-12 transition-colors"
                    required
                    disabled={isLoggingIn || apiStatus === 'offline'}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="absolute right-2 top-1/2 -translate-y-1/2 h-8 w-8 p-0 hover:bg-gray-100"
                    onClick={() => setShowPassword(!showPassword)}
                    disabled={isLoggingIn}
                  >
                    {showPassword ? (
                      <EyeOff className="w-4 h-4 text-gray-500" />
                    ) : (
                      <Eye className="w-4 h-4 text-gray-500" />
                    )}
                  </Button>
                </div>
              </div>
              
              <Button 
                type="submit" 
                className="w-full h-12 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white font-medium rounded-lg shadow-lg hover:shadow-xl transition-all duration-200 transform hover:scale-[1.02] disabled:opacity-50 disabled:cursor-not-allowed disabled:transform-none"
                disabled={isLoggingIn || apiStatus === 'offline'}
              >
                {isLoggingIn ? (
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    กำลังเข้าสู่ระบบ...
                  </div>
                ) : apiStatus === 'offline' ? (
                  <div className="flex items-center gap-2">
                    <WifiOff className="w-4 h-4" />
                    ไม่สามารถเชื่อมต่อได้
                  </div>
                ) : (
                  'เข้าสู่ระบบ'
                )}
              </Button>
            </form>
            
            <div className="text-center text-sm text-gray-500 border-t pt-4">
              <p className="mb-2">ระบบจัดการหมู่บ้านอัจฉริยะ v2.0 - JWT Authentication</p>
              <div className="bg-gray-50 p-3 rounded-lg text-left">
                <p className="font-medium text-gray-700 mb-1">Demo Account:</p>
                <p className="text-xs">Email: <span className="font-mono bg-blue-100 px-1 rounded">admin@village.com</span></p>
                <p className="text-xs">Password: <span className="font-mono bg-blue-100 px-1 rounded">Admin123!</span></p>
                <p className="text-xs text-gray-500 mt-2">
                  หมายเหตุ: ใช้อีเมลแทนชื่อผู้ใช้ในระบบใหม่
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

export default LoginPage

