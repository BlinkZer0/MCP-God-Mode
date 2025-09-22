import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { Box, Typography, Card, CardContent } from '@mui/material';
const Dashboard = () => {
    return (_jsxs(Box, { children: [_jsx(Typography, { variant: "h4", gutterBottom: true, children: "Dashboard" }), _jsxs(Box, { sx: {
                    display: 'grid',
                    gridTemplateColumns: { xs: '1fr', md: 'repeat(2, 1fr)', lg: 'repeat(3, 1fr)' },
                    gap: 3
                }, children: [_jsx(Card, { children: _jsxs(CardContent, { children: [_jsx(Typography, { variant: "h6", gutterBottom: true, children: "System Status" }), _jsx(Typography, { variant: "body2", color: "text.secondary", children: "All systems operational" })] }) }), _jsx(Card, { children: _jsxs(CardContent, { children: [_jsx(Typography, { variant: "h6", gutterBottom: true, children: "Active Tools" }), _jsx(Typography, { variant: "body2", color: "text.secondary", children: "14 tools available" })] }) }), _jsx(Card, { children: _jsxs(CardContent, { children: [_jsx(Typography, { variant: "h6", gutterBottom: true, children: "Recent Activity" }), _jsx(Typography, { variant: "body2", color: "text.secondary", children: "No recent activity" })] }) })] })] }));
};
export default Dashboard;
