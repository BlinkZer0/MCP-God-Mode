import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline, Box } from '@mui/material';
import { io, Socket } from 'socket.io-client';

// Import components
import Layout from './components/Layout';
import Login from './components/Login';
import Dashboard from './pages/Dashboard';
import Monitoring from './pages/Monitoring';
import Workflows from './pages/Workflows';
import Plugins from './pages/Plugins';
import Tools from './pages/Tools';
import Settings from './pages/Settings';

// Import contexts
import { AuthContext } from './contexts/AuthContext';
import { SocketContext } from './contexts/SocketContext';
import { ThemeContext } from './contexts/ThemeContext';

// Import types
import { User, AuthContextType } from './types/auth';
import { SocketContextType } from './types/socket';

// API configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:3000/api/v1';
const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || 'http://localhost:3000';

// App component
function App() {
  // State
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [isDarkMode, setIsDarkMode] = useState(false);
  const [socket, setSocket] = useState<Socket | null>(null);

  // Theme
  const theme = createTheme({
    palette: {
      mode: isDarkMode ? 'dark' : 'light',
      primary: {
        main: '#007AFF',
      },
      secondary: {
        main: '#FF6B6B',
      },
      background: {
        default: isDarkMode ? '#121212' : '#f5f5f5',
        paper: isDarkMode ? '#1e1e1e' : '#ffffff',
      },
    },
    typography: {
      fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
      h1: {
        fontSize: '2.5rem',
        fontWeight: 700,
      },
      h2: {
        fontSize: '2rem',
        fontWeight: 600,
      },
      h3: {
        fontSize: '1.5rem',
        fontWeight: 600,
      },
      h4: {
        fontSize: '1.25rem',
        fontWeight: 500,
      },
      h5: {
        fontSize: '1.125rem',
        fontWeight: 500,
      },
      h6: {
        fontSize: '1rem',
        fontWeight: 500,
      },
    },
    components: {
      MuiButton: {
        styleOverrides: {
          root: {
            borderRadius: 8,
            textTransform: 'none',
            fontWeight: 500,
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            borderRadius: 12,
            boxShadow: isDarkMode 
              ? '0 4px 20px rgba(0, 0, 0, 0.3)' 
              : '0 4px 20px rgba(0, 0, 0, 0.1)',
          },
        },
      },
    },
  });

  // Auth context value
  const authContextValue: AuthContextType = {
    user,
    isAuthenticated,
    login: async (credentials) => {
      try {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(credentials),
        });

        if (response.ok) {
          const userData = await response.json();
          setUser(userData.user);
          setIsAuthenticated(true);
          return { success: true };
        } else {
          const error = await response.json();
          return { success: false, error: error.message };
        }
      } catch (error) {
        return { success: false, error: 'Network error' };
      }
    },
    logout: () => {
      setUser(null);
      setIsAuthenticated(false);
      if (socket) {
        socket.disconnect();
        setSocket(null);
      }
    },
  };

  // Socket context value
  const socketContextValue: SocketContextType = {
    socket,
    connect: () => {
      if (!socket && isAuthenticated) {
        const newSocket = io(SOCKET_URL, {
          auth: {
            token: user?.token,
          },
        });
        setSocket(newSocket);
      }
    },
    disconnect: () => {
      if (socket) {
        socket.disconnect();
        setSocket(null);
      }
    },
  };

  // Theme context value
  const themeContextValue = {
    isDarkMode,
    toggleTheme: () => setIsDarkMode(!isDarkMode),
  };

  // Check authentication status on mount
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const token = localStorage.getItem('token');
        if (token) {
          const response = await fetch(`${API_BASE_URL}/auth/verify`, {
            headers: {
              'Authorization': `Bearer ${token}`,
            },
          });
          if (response.ok) {
            const userData = await response.json();
            setUser(userData.user);
            setIsAuthenticated(true);
          }
        }
      } catch (error) {
        console.error('Auth check failed:', error);
      } finally {
        setIsLoading(false);
      }
    };

    checkAuth();
  }, []);

  // Connect socket when authenticated
  useEffect(() => {
    if (isAuthenticated && !socket) {
      socketContextValue.connect();
    }
  }, [isAuthenticated, socket]);

  if (isLoading) {
    return (
      <Box
        display="flex"
        justifyContent="center"
        alignItems="center"
        minHeight="100vh"
        bgcolor="background.default"
      >
        <div>Loading...</div>
      </Box>
    );
  }

  return (
    <ThemeContext.Provider value={themeContextValue}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <AuthContext.Provider value={authContextValue}>
          <SocketContext.Provider value={socketContextValue}>
            <Router>
              <Box bgcolor="background.default" minHeight="100vh">
                {isAuthenticated ? (
                  <Layout>
                    <Routes>
                      <Route path="/" element={<Navigate to="/dashboard" replace />} />
                      <Route path="/dashboard" element={<Dashboard />} />
                      <Route path="/monitoring" element={<Monitoring />} />
                      <Route path="/workflows" element={<Workflows />} />
                      <Route path="/plugins" element={<Plugins />} />
                      <Route path="/tools" element={<Tools />} />
                      <Route path="/settings" element={<Settings />} />
                      <Route path="*" element={<Navigate to="/dashboard" replace />} />
                    </Routes>
                  </Layout>
                ) : (
                  <Routes>
                    <Route path="/login" element={<Login />} />
                    <Route path="*" element={<Navigate to="/login" replace />} />
                  </Routes>
                )}
              </Box>
            </Router>
          </SocketContext.Provider>
        </AuthContext.Provider>
      </ThemeProvider>
    </ThemeContext.Provider>
  );
}

export default App;
