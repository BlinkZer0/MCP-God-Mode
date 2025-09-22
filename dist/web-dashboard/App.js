import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline, Box } from '@mui/material';
import { io } from 'socket.io-client';
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
// API configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:3000/api/v1';
const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || 'http://localhost:3000';
// App component
function App() {
    // State
    const [user, setUser] = useState(null);
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isLoading, setIsLoading] = useState(true);
    const [isDarkMode, setIsDarkMode] = useState(false);
    const [socket, setSocket] = useState(null);
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
    const authContextValue = {
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
                }
                else {
                    const error = await response.json();
                    return { success: false, error: error.message };
                }
            }
            catch (error) {
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
    const socketContextValue = {
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
            }
            catch (error) {
                console.error('Auth check failed:', error);
            }
            finally {
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
        return (_jsx(Box, { display: "flex", justifyContent: "center", alignItems: "center", minHeight: "100vh", bgcolor: "background.default", children: _jsx("div", { children: "Loading..." }) }));
    }
    return (_jsx(ThemeContext.Provider, { value: themeContextValue, children: _jsxs(ThemeProvider, { theme: theme, children: [_jsx(CssBaseline, {}), _jsx(AuthContext.Provider, { value: authContextValue, children: _jsx(SocketContext.Provider, { value: socketContextValue, children: _jsx(Router, { children: _jsx(Box, { bgcolor: "background.default", minHeight: "100vh", children: isAuthenticated ? (_jsx(Layout, { children: _jsxs(Routes, { children: [_jsx(Route, { path: "/", element: _jsx(Navigate, { to: "/dashboard", replace: true }) }), _jsx(Route, { path: "/dashboard", element: _jsx(Dashboard, {}) }), _jsx(Route, { path: "/monitoring", element: _jsx(Monitoring, {}) }), _jsx(Route, { path: "/workflows", element: _jsx(Workflows, {}) }), _jsx(Route, { path: "/plugins", element: _jsx(Plugins, {}) }), _jsx(Route, { path: "/tools", element: _jsx(Tools, {}) }), _jsx(Route, { path: "/settings", element: _jsx(Settings, {}) }), _jsx(Route, { path: "*", element: _jsx(Navigate, { to: "/dashboard", replace: true }) })] }) })) : (_jsxs(Routes, { children: [_jsx(Route, { path: "/login", element: _jsx(Login, {}) }), _jsx(Route, { path: "*", element: _jsx(Navigate, { to: "/login", replace: true }) })] })) }) }) }) })] }) }));
}
export default App;
