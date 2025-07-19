import { useState, useEffect } from 'react'
import { 
  Home, 
  Users, 
  DollarSign, 
  Settings, 
  BarChart3, 
  FileText, 
  Shield, 
  Bell,
  Search,
  Menu,
  LogOut,
  User,
  ChevronDown,
  Activity,
  TrendingUp,
  UserCheck,
  AlertTriangle,
  X,
  Sun,
  Moon
} from 'lucide-react'
import { Button } from '@/components/ui/button.jsx'
import { Input } from '@/components/ui/input.jsx'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card.jsx'
import { Badge } from '@/components/ui/badge.jsx'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar.jsx'
import { 
  DropdownMenu, 
  DropdownMenuContent, 
  DropdownMenuItem, 
  DropdownMenuLabel, 
  DropdownMenuSeparator, 
  DropdownMenuTrigger 
} from '@/components/ui/dropdown-menu.jsx'
import { Sidebar, SidebarContent, SidebarHeader, SidebarMenu, SidebarMenuItem, SidebarMenuButton, SidebarProvider } from '@/components/ui/sidebar.jsx'
import { useAuth } from '../../contexts/AuthContext'
import UserManagement from './UserManagement.jsx'
import '../../styles/App.css'

const sidebarItems = [
  { icon: Home, label: 'Dashboard' },
  { icon: Users, label: 'User Management' },
  { icon: DollarSign, label: 'Financial Management' },
  { icon: BarChart3, label: 'Reports & Analytics' },
  { icon: FileText, label: 'Document Management' },
  { icon: Shield, label: 'Security & Audit' },
  { icon: Settings, label: 'System Settings' },
]

const statsCards = [
  {
    title: 'Total Users',
    value: '1,234',
    change: '+12%',
    trend: 'up',
    icon: Users,
    color: 'text-blue-600',
    bgColor: 'bg-blue-50'
  },
  {
    title: 'Monthly Revenue',
    value: '฿2,456,789',
    change: '+8.2%',
    trend: 'up',
    icon: DollarSign,
    color: 'text-green-600',
    bgColor: 'bg-green-50'
  },
  {
    title: 'Active Sessions',
    value: '89',
    change: '+5.1%',
    trend: 'up',
    icon: Activity,
    color: 'text-purple-600',
    bgColor: 'bg-purple-50'
  },
  {
    title: 'System Health',
    value: '99.9%',
    change: '+0.1%',
    trend: 'up',
    icon: TrendingUp,
    color: 'text-emerald-600',
    bgColor: 'bg-emerald-50'
  }
]

const recentActivities = [
  {
    user: 'John Doe',
    action: 'Created new user account',
    time: '2 minutes ago',
    type: 'user',
    avatar: 'JD'
  },
  {
    user: 'Jane Smith',
    action: 'Updated financial report',
    time: '15 minutes ago',
    type: 'finance',
    avatar: 'JS'
  },
  {
    user: 'Mike Johnson',
    action: 'System backup completed',
    time: '1 hour ago',
    type: 'system',
    avatar: 'MJ'
  },
  {
    user: 'Sarah Wilson',
    action: 'Security audit performed',
    time: '2 hours ago',
    type: 'security',
    avatar: 'SW'
  }
]

function SuperAdminDashboard() {
  const { user, logout } = useAuth()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [activeItem, setActiveItem] = useState('Dashboard')
  const [darkMode, setDarkMode] = useState(false)
  const [currentTime, setCurrentTime] = useState(new Date())

  // Handle logout
  const handleLogout = async () => {
    try {
      await logout()
      // Navigation will be handled by AuthContext
    } catch (error) {
      console.error('Logout error:', error)
    }
  }

  // Update time every minute
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date())
    }, 60000)
    return () => clearInterval(timer)
  }, [])

  // Handle responsive sidebar
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth < 1024) {
        setSidebarOpen(false)
      } else {
        setSidebarOpen(true)
      }
    }

    handleResize()
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [])

  const toggleDarkMode = () => {
    setDarkMode(!darkMode)
    document.documentElement.classList.toggle('dark')
  }

  return (
    <div className={`min-h-screen ${darkMode ? 'dark' : ''}`}>
      <SidebarProvider>
        <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex w-full">
          {/* Sidebar */}
          <Sidebar className={`border-r bg-white dark:bg-gray-800 transition-all duration-300 ${
            sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
          }`}>
            <SidebarHeader className="border-b dark:border-gray-700 p-6">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 bg-gradient-to-br from-blue-600 to-purple-600 rounded-lg flex items-center justify-center">
                    <Home className="w-6 h-6 text-white" />
                  </div>
                  <div>
                    <h2 className="text-lg font-bold text-gray-900 dark:text-white">Village Admin</h2>
                    <p className="text-sm text-gray-500 dark:text-gray-400">SuperAdmin Panel</p>
                  </div>
                </div>
                <Button 
                  variant="ghost" 
                  size="sm" 
                  className="lg:hidden"
                  onClick={() => setSidebarOpen(false)}
                >
                  <X className="w-4 h-4" />
                </Button>
              </div>
            </SidebarHeader>
            
            <SidebarContent className="p-4">
              <SidebarMenu>
                {sidebarItems.map((item) => (
                  <SidebarMenuItem key={item.label}>
                    <SidebarMenuButton
                      onClick={() => {
                        setActiveItem(item.label)
                        if (window.innerWidth < 1024) setSidebarOpen(false)
                      }}
                      className={`w-full justify-start space-x-3 ${
                        activeItem === item.label 
                          ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-800' 
                          : 'text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
                      }`}
                    >
                      <item.icon className="w-5 h-5" />
                      <span>{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarContent>
          </Sidebar>

          {/* Overlay for mobile */}
          {sidebarOpen && (
            <div 
              className="fixed inset-0 bg-black bg-opacity-50 z-40 lg:hidden"
              onClick={() => setSidebarOpen(false)}
            />
          )}

          {/* Main Content */}
          <div className="flex-1 flex flex-col min-w-0">
            {/* Fixed Header */}
            <header className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-4 lg:px-6 py-4 sticky top-0 z-30">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <Button 
                    variant="ghost" 
                    size="sm"
                    onClick={() => setSidebarOpen(!sidebarOpen)}
                    className="lg:hidden"
                  >
                    <Menu className="w-5 h-5" />
                  </Button>
                  <div>
                    <h1 className="text-xl lg:text-2xl font-bold text-gray-900 dark:text-white">{activeItem}</h1>
                    <p className="text-sm text-gray-500 dark:text-gray-400 hidden sm:block">
                      {currentTime.toLocaleDateString('th-TH', { 
                        weekday: 'long', 
                        year: 'numeric', 
                        month: 'long', 
                        day: 'numeric' 
                      })}
                    </p>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2 lg:space-x-4">
                  {/* Search - Hidden on mobile */}
                  <div className="relative hidden md:block">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                    <Input 
                      placeholder="Search..." 
                      className="pl-10 w-48 lg:w-64 dark:bg-gray-700 dark:border-gray-600"
                    />
                  </div>
                  
                  {/* Dark Mode Toggle */}
                  <Button 
                    variant="ghost" 
                    size="sm" 
                    onClick={toggleDarkMode}
                    className="hidden sm:flex"
                  >
                    {darkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
                  </Button>
                  
                  {/* Notifications */}
                  <Button variant="ghost" size="sm" className="relative">
                    <Bell className="w-5 h-5" />
                    <Badge className="absolute -top-1 -right-1 w-5 h-5 p-0 flex items-center justify-center text-xs bg-red-500">
                      3
                    </Badge>
                  </Button>
                  
                  {/* User Menu */}
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" className="flex items-center space-x-2">
                        <Avatar className="w-8 h-8">
                          <AvatarImage src="/api/placeholder/32/32" />
                          <AvatarFallback className="bg-blue-600 text-white">SA</AvatarFallback>
                        </Avatar>
                        <div className="text-left hidden lg:block">
                          <p className="text-sm font-medium dark:text-white">Super Admin</p>
                          <p className="text-xs text-gray-500 dark:text-gray-400">admin@village.com</p>
                        </div>
                        <ChevronDown className="w-4 h-4 hidden lg:block" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-56">
                      <DropdownMenuLabel>My Account</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem>
                        <User className="mr-2 h-4 w-4" />
                        Profile
                      </DropdownMenuItem>
                      <DropdownMenuItem>
                        <Settings className="mr-2 h-4 w-4" />
                        Settings
                      </DropdownMenuItem>
                      <DropdownMenuItem className="sm:hidden" onClick={toggleDarkMode}>
                        {darkMode ? <Sun className="mr-2 h-4 w-4" /> : <Moon className="mr-2 h-4 w-4" />}
                        {darkMode ? 'Light Mode' : 'Dark Mode'}
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem className="text-red-600" onClick={handleLogout}>
                        <LogOut className="mr-2 h-4 w-4" />
                        Logout
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </div>
            </header>

            {/* Dashboard Content */}
            <main className="flex-1 p-4 lg:p-6 overflow-auto">
              {activeItem === 'Dashboard' && (
                <div className="space-y-6">
                  {/* Stats Cards */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-6">
                    {statsCards.map((stat, index) => (
                      <Card key={index} className="hover:shadow-lg transition-all duration-200 dark:bg-gray-800 dark:border-gray-700">
                        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                          <CardTitle className="text-sm font-medium text-gray-600 dark:text-gray-400">
                            {stat.title}
                          </CardTitle>
                          <div className={`w-10 h-10 rounded-lg ${stat.bgColor} dark:bg-opacity-20 flex items-center justify-center`}>
                            <stat.icon className={`w-5 h-5 ${stat.color}`} />
                          </div>
                        </CardHeader>
                        <CardContent>
                          <div className="text-2xl font-bold text-gray-900 dark:text-white">{stat.value}</div>
                          <div className="flex items-center space-x-1 text-sm">
                            <TrendingUp className="w-4 h-4 text-green-500" />
                            <span className="text-green-600 dark:text-green-400">{stat.change}</span>
                            <span className="text-gray-500 dark:text-gray-400">from last month</span>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>

                  {/* Charts and Activities */}
                  <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                    {/* Chart Card */}
                    <Card className="xl:col-span-2 dark:bg-gray-800 dark:border-gray-700">
                      <CardHeader>
                        <CardTitle className="dark:text-white">System Overview</CardTitle>
                        <CardDescription className="dark:text-gray-400">
                          Real-time system performance and usage statistics
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="h-64 bg-gradient-to-br from-blue-50 to-purple-50 dark:from-blue-900/20 dark:to-purple-900/20 rounded-lg flex items-center justify-center">
                          <div className="text-center">
                            <BarChart3 className="w-16 h-16 text-blue-500 mx-auto mb-4" />
                            <p className="text-gray-600 dark:text-gray-300">Chart Component</p>
                            <p className="text-sm text-gray-500 dark:text-gray-400">Interactive charts will be displayed here</p>
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                    {/* Recent Activities */}
                    <Card className="dark:bg-gray-800 dark:border-gray-700">
                      <CardHeader>
                        <CardTitle className="dark:text-white">Recent Activities</CardTitle>
                        <CardDescription className="dark:text-gray-400">
                          Latest system activities and user actions
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-4">
                          {recentActivities.map((activity, index) => (
                            <div key={index} className="flex items-start space-x-3">
                              <Avatar className="w-8 h-8">
                                <AvatarFallback className={`text-xs ${
                                  activity.type === 'user' ? 'bg-blue-100 text-blue-700' :
                                  activity.type === 'finance' ? 'bg-green-100 text-green-700' :
                                  activity.type === 'system' ? 'bg-purple-100 text-purple-700' :
                                  'bg-orange-100 text-orange-700'
                                }`}>
                                  {activity.avatar}
                                </AvatarFallback>
                              </Avatar>
                              <div className="flex-1 min-w-0">
                                <p className="text-sm font-medium text-gray-900 dark:text-white">
                                  {activity.user}
                                </p>
                                <p className="text-sm text-gray-600 dark:text-gray-300">
                                  {activity.action}
                                </p>
                                <p className="text-xs text-gray-500 dark:text-gray-400">
                                  {activity.time}
                                </p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                </div>
              )}

              {activeItem === 'User Management' && (
                <UserManagement />
              )}

              {activeItem !== 'Dashboard' && activeItem !== 'User Management' && (
                <div className="flex items-center justify-center h-64">
                  <div className="text-center">
                    <div className="text-6xl mb-4">🚧</div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                      {activeItem}
                    </h3>
                    <p className="text-gray-600 dark:text-gray-400">
                      This section is under development
                    </p>
                  </div>
                </div>
              )}
            </main>
          </div>
        </div>
      </SidebarProvider>
    </div>
  )
}

export default SuperAdminDashboard

