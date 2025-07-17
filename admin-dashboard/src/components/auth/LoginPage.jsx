import React, { useState } from 'react'
import { Button } from '../ui/button.jsx'
import { Input } from '../ui/input.jsx'
import { Label } from '../ui/label.jsx'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card.jsx'
import { Home, User, Lock, Eye, EyeOff } from 'lucide-react'
import '../../styles/App.css'

function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)

  const handleLogin = async (e) => {
    e.preventDefault()
    setIsLoading(true)
    
    // Simulate login process
    setTimeout(() => {
      setIsLoading(false)
      const success = onLogin({ username, password })
      if (!success) {
        alert('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง')
      }
    }, 1500)
  }

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
                ระบบจัดการหมู่บ้านอัจฉริยะ
              </CardDescription>
            </div>
          </CardHeader>
          
          <CardContent className="space-y-6">
            <form onSubmit={handleLogin} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username" className="text-sm font-medium text-gray-700 flex items-center gap-2">
                  <User className="w-4 h-4 text-green-500" />
                  ชื่อผู้ใช้
                </Label>
                <Input
                  id="username"
                  type="text"
                  placeholder="กรอกชื่อผู้ใช้"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="h-12 border-2 border-blue-100 focus:border-blue-400 rounded-lg transition-colors"
                  required
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
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="absolute right-2 top-1/2 -translate-y-1/2 h-8 w-8 p-0 hover:bg-gray-100"
                    onClick={() => setShowPassword(!showPassword)}
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
                className="w-full h-12 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white font-medium rounded-lg shadow-lg hover:shadow-xl transition-all duration-200 transform hover:scale-[1.02]"
                disabled={isLoading}
              >
                {isLoading ? (
                  <div className="flex items-center gap-2">
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    กำลังเข้าสู่ระบบ...
                  </div>
                ) : (
                  'เข้าสู่ระบบ'
                )}
              </Button>
            </form>
            
            <div className="text-center text-sm text-gray-500 border-t pt-4">
              <p className="mb-2">ระบบจัดการหมู่บ้านอัจฉริยะ v2.0</p>
              <div className="bg-gray-50 p-3 rounded-lg text-left">
                <p className="font-medium text-gray-700 mb-1">Demo Account:</p>
                <p className="text-xs">Username: <span className="font-mono bg-blue-100 px-1 rounded">superadmin</span></p>
                <p className="text-xs">Password: <span className="font-mono bg-blue-100 px-1 rounded">Admin123!</span></p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

export default LoginPage

