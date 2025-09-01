"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = __importDefault(require("react"));
const material_1 = require("@mui/material");
const icons_material_1 = require("@mui/icons-material");
const react_router_dom_1 = require("react-router-dom");
const ThemeContext_1 = require("../contexts/ThemeContext");
const Layout = ({ children }) => {
    const [drawerOpen, setDrawerOpen] = react_1.default.useState(false);
    const navigate = (0, react_router_dom_1.useNavigate)();
    const theme = (0, material_1.useTheme)();
    const { isDarkMode, toggleTheme } = (0, ThemeContext_1.useTheme)();
    const menuItems = [
        { text: 'Dashboard', icon: (0, jsx_runtime_1.jsx)(icons_material_1.Dashboard, {}), path: '/dashboard' },
        { text: 'Monitoring', icon: (0, jsx_runtime_1.jsx)(icons_material_1.Monitor, {}), path: '/monitoring' },
        { text: 'Workflows', icon: (0, jsx_runtime_1.jsx)(icons_material_1.Work, {}), path: '/workflows' },
        { text: 'Plugins', icon: (0, jsx_runtime_1.jsx)(icons_material_1.Extension, {}), path: '/plugins' },
        { text: 'Tools', icon: (0, jsx_runtime_1.jsx)(icons_material_1.Build, {}), path: '/tools' },
        { text: 'Settings', icon: (0, jsx_runtime_1.jsx)(icons_material_1.Settings, {}), path: '/settings' },
    ];
    const handleNavigation = (path) => {
        navigate(path);
        setDrawerOpen(false);
    };
    return ((0, jsx_runtime_1.jsxs)(material_1.Box, { sx: { display: 'flex' }, children: [(0, jsx_runtime_1.jsx)(material_1.AppBar, { position: "fixed", sx: { zIndex: theme.zIndex.drawer + 1 }, children: (0, jsx_runtime_1.jsxs)(material_1.Toolbar, { children: [(0, jsx_runtime_1.jsx)(material_1.IconButton, { color: "inherit", "aria-label": "open drawer", edge: "start", onClick: () => setDrawerOpen(true), sx: { mr: 2 }, children: (0, jsx_runtime_1.jsx)(icons_material_1.Menu, {}) }), (0, jsx_runtime_1.jsx)(material_1.Typography, { variant: "h6", noWrap: true, component: "div", sx: { flexGrow: 1 }, children: "MCP God Mode" }), (0, jsx_runtime_1.jsx)(material_1.IconButton, { color: "inherit", onClick: toggleTheme, children: isDarkMode ? '☀️' : '🌙' })] }) }), (0, jsx_runtime_1.jsxs)(material_1.Drawer, { variant: "temporary", open: drawerOpen, onClose: () => setDrawerOpen(false), sx: {
                    width: 240,
                    flexShrink: 0,
                    '& .MuiDrawer-paper': {
                        width: 240,
                        boxSizing: 'border-box',
                    },
                }, children: [(0, jsx_runtime_1.jsx)(material_1.Toolbar, {}), (0, jsx_runtime_1.jsx)(material_1.Box, { sx: { overflow: 'auto' }, children: (0, jsx_runtime_1.jsx)(material_1.List, { children: menuItems.map((item) => ((0, jsx_runtime_1.jsxs)(material_1.ListItem, { onClick: () => handleNavigation(item.path), sx: { cursor: 'pointer' }, children: [(0, jsx_runtime_1.jsx)(material_1.ListItemIcon, { children: item.icon }), (0, jsx_runtime_1.jsx)(material_1.ListItemText, { primary: item.text })] }, item.text))) }) })] }), (0, jsx_runtime_1.jsxs)(material_1.Box, { component: "main", sx: { flexGrow: 1, p: 3 }, children: [(0, jsx_runtime_1.jsx)(material_1.Toolbar, {}), children] })] }));
};
exports.default = Layout;
