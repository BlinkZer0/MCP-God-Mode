import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import React from 'react';
import { Box, AppBar, Toolbar, Typography, IconButton, Drawer, List, ListItem, ListItemIcon, ListItemText, useTheme } from '@mui/material';
import { Menu as MenuIcon, Dashboard, Monitor, Work, Extension, Build, Settings } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useTheme as useAppTheme } from '../contexts/ThemeContext';
const Layout = ({ children }) => {
    const [drawerOpen, setDrawerOpen] = React.useState(false);
    const navigate = useNavigate();
    const theme = useTheme();
    const { isDarkMode, toggleTheme } = useAppTheme();
    const menuItems = [
        { text: 'Dashboard', icon: _jsx(Dashboard, {}), path: '/dashboard' },
        { text: 'Monitoring', icon: _jsx(Monitor, {}), path: '/monitoring' },
        { text: 'Workflows', icon: _jsx(Work, {}), path: '/workflows' },
        { text: 'Plugins', icon: _jsx(Extension, {}), path: '/plugins' },
        { text: 'Tools', icon: _jsx(Build, {}), path: '/tools' },
        { text: 'Settings', icon: _jsx(Settings, {}), path: '/settings' },
    ];
    const handleNavigation = (path) => {
        navigate(path);
        setDrawerOpen(false);
    };
    return (_jsxs(Box, { sx: { display: 'flex' }, children: [_jsx(AppBar, { position: "fixed", sx: { zIndex: theme.zIndex.drawer + 1 }, children: _jsxs(Toolbar, { children: [_jsx(IconButton, { color: "inherit", "aria-label": "open drawer", edge: "start", onClick: () => setDrawerOpen(true), sx: { mr: 2 }, children: _jsx(MenuIcon, {}) }), _jsx(Typography, { variant: "h6", noWrap: true, component: "div", sx: { flexGrow: 1 }, children: "MCP God Mode" }), _jsx(IconButton, { color: "inherit", onClick: toggleTheme, children: isDarkMode ? '☀️' : '🌙' })] }) }), _jsxs(Drawer, { variant: "temporary", open: drawerOpen, onClose: () => setDrawerOpen(false), sx: {
                    width: 240,
                    flexShrink: 0,
                    '& .MuiDrawer-paper': {
                        width: 240,
                        boxSizing: 'border-box',
                    },
                }, children: [_jsx(Toolbar, {}), _jsx(Box, { sx: { overflow: 'auto' }, children: _jsx(List, { children: menuItems.map((item) => (_jsxs(ListItem, { onClick: () => handleNavigation(item.path), sx: { cursor: 'pointer' }, children: [_jsx(ListItemIcon, { children: item.icon }), _jsx(ListItemText, { primary: item.text })] }, item.text))) }) })] }), _jsxs(Box, { component: "main", sx: { flexGrow: 1, p: 3 }, children: [_jsx(Toolbar, {}), children] })] }));
};
export default Layout;
