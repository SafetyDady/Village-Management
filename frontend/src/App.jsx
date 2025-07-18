import React, { useState } from 'react';
import LoginPage from './components/auth/LoginPage';
import SuperAdminDashboard from './components/dashboard/SuperAdminDashboard';
import './styles/App.css';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);

  const handleLogin = (credentials) => {
    // Simple authentication logic
    if (credentials.username === 'superadmin' && credentials.password === 'Admin123!') {
      setIsAuthenticated(true);
      setUser({
        username: 'superadmin',
        name: 'Super Admin',
        email: 'admin@village.com',
        role: 'superadmin'
      });
      return true;
    }
    return false;
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    setUser(null);
  };

  if (!isAuthenticated) {
    return <LoginPage onLogin={handleLogin} />;
  }

  return <SuperAdminDashboard user={user} onLogout={handleLogout} />;
}

export default App;

