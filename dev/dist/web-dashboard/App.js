"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const react_router_dom_1 = require("react-router-dom");
const styles_1 = require("@mui/material/styles");
const material_1 = require("@mui/material");
const socket_io_client_1 = require("socket.io-client");
// Import components
const Layout_1 = __importDefault(require("./components/Layout"));
const Login_1 = __importDefault(require("./components/Login"));
const Dashboard_1 = __importDefault(require("./pages/Dashboard"));
const Monitoring_1 = __importDefault(require("./pages/Monitoring"));
const Workflows_1 = __importDefault(require("./pages/Workflows"));
const Plugins_1 = __importDefault(require("./pages/Plugins"));
const Tools_1 = __importDefault(require("./pages/Tools"));
const Settings_1 = __importDefault(require("./pages/Settings"));
// Import contexts
const AuthContext_1 = require("./contexts/AuthContext");
const SocketContext_1 = require("./contexts/SocketContext");
const ThemeContext_1 = require("./contexts/ThemeContext");
// API configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:3000/api/v1';
const SOCKET_URL = process.env.REACT_APP_SOCKET_URL || 'http://localhost:3000';
// App component
function App() {
    // State
    const [user, setUser] = (0, react_1.useState)(null);
    const [isAuthenticated, setIsAuthenticated] = (0, react_1.useState)(false);
    const [isLoading, setIsLoading] = (0, react_1.useState)(true);
    const [isDarkMode, setIsDarkMode] = (0, react_1.useState)(false);
    const [socket, setSocket] = (0, react_1.useState)(null);
    // Theme
    const theme = (0, styles_1.createTheme)({
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
                const newSocket = (0, socket_io_client_1.io)(SOCKET_URL, {
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
    (0, react_1.useEffect)(() => {
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
    (0, react_1.useEffect)(() => {
        if (isAuthenticated && !socket) {
            socketContextValue.connect();
        }
    }, [isAuthenticated, socket]);
    if (isLoading) {
        return ((0, jsx_runtime_1.jsx)(material_1.Box, { display: "flex", justifyContent: "center", alignItems: "center", minHeight: "100vh", bgcolor: "background.default", children: (0, jsx_runtime_1.jsx)("div", { children: "Loading..." }) }));
    }
    return ((0, jsx_runtime_1.jsx)(ThemeContext_1.ThemeContext.Provider, { value: themeContextValue, children: (0, jsx_runtime_1.jsxs)(styles_1.ThemeProvider, { theme: theme, children: [(0, jsx_runtime_1.jsx)(material_1.CssBaseline, {}), (0, jsx_runtime_1.jsx)(AuthContext_1.AuthContext.Provider, { value: authContextValue, children: (0, jsx_runtime_1.jsx)(SocketContext_1.SocketContext.Provider, { value: socketContextValue, children: (0, jsx_runtime_1.jsx)(react_router_dom_1.BrowserRouter, { children: (0, jsx_runtime_1.jsx)(material_1.Box, { bgcolor: "background.default", minHeight: "100vh", children: isAuthenticated ? ((0, jsx_runtime_1.jsx)(Layout_1.default, { children: (0, jsx_runtime_1.jsxs)(react_router_dom_1.Routes, { children: [(0, jsx_runtime_1.jsx)(react_router_dom_1.Route, { path: "/", element: (0, jsx_runtime_1.jsx)(react_router_dom_1.Navigate, { to: "/dashboard", replace: true }) }), (0, jsx_runtime_1.jsx)(react_router_dom_1.Route, { path: "/dashboard", element: (0, jsx_runtime_1.jsx)(Dashboard_1.default, {}) }), (0, jsx_runtime_1.jsx)(react_router_dom_1.Route, { path: "/monitoring", element: (0, jsx_runtime_1.jsx)(Monitoring_1.default, {}) }), (0, jsx_runtime_1.jsx)(react_router_dom_1.Route, { path: "/workflows", element: (0, jsx_runtime_1.jsx)(Workflows_1.default, {}) }), (0, jsx_runtime_1.jsx)(react_router_dom_1.Route, { path: "/plugins", element: (0, jsx_runtime_1.jsx)(Plugins_1.default, {}) }), (0, jsx_runtime_1.jsx)(react_router_dom_1.Route, { path: "/tools", element: (0, jsx_runtime_1.jsx)(Tools_1.default, {}) }), (0, jsx_runtime_1.jsx)(react_router_dom_1.Route, { path: "/settings", element: (0, jsx_runtime_1.jsx)(Settings_1.default, {}) }), (0, jsx_runtime_1.jsx)(react_router_dom_1.Route, { path: "*", element: (0, jsx_runtime_1.jsx)(react_router_dom_1.Navigate, { to: "/dashboard", replace: true }) })] }) })) : ((0, jsx_runtime_1.jsxs)(react_router_dom_1.Routes, { children: [(0, jsx_runtime_1.jsx)(react_router_dom_1.Route, { path: "/login", element: (0, jsx_runtime_1.jsx)(Login_1.default, {}) }), (0, jsx_runtime_1.jsx)(react_router_dom_1.Route, { path: "*", element: (0, jsx_runtime_1.jsx)(react_router_dom_1.Navigate, { to: "/login", replace: true }) })] })) }) }) }) })] }) }));
}
exports.default = App;
