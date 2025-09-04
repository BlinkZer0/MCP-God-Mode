import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from 'react';
import { Box, Card, CardContent, TextField, Button, Typography, Alert } from '@mui/material';
import { useAuth } from '../contexts/AuthContext';
const Login = () => {
    const [credentials, setCredentials] = useState({
        username: '',
        password: '',
    });
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const { login } = useAuth();
    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setIsLoading(true);
        try {
            const result = await login(credentials);
            if (!result.success) {
                setError(result.error || 'Login failed');
            }
        }
        catch (err) {
            setError('An unexpected error occurred');
        }
        finally {
            setIsLoading(false);
        }
    };
    const handleChange = (field) => (e) => {
        setCredentials(prev => ({
            ...prev,
            [field]: e.target.value,
        }));
    };
    return (_jsx(Box, { display: "flex", justifyContent: "center", alignItems: "center", minHeight: "100vh", bgcolor: "background.default", children: _jsx(Card, { sx: { maxWidth: 400, width: '100%', mx: 2 }, children: _jsxs(CardContent, { sx: { p: 4 }, children: [_jsx(Typography, { variant: "h4", component: "h1", gutterBottom: true, align: "center", children: "MCP God Mode" }), _jsx(Typography, { variant: "body1", color: "text.secondary", align: "center", gutterBottom: true, children: "Sign in to your account" }), _jsxs(Box, { component: "form", onSubmit: handleSubmit, sx: { mt: 3 }, children: [error && (_jsx(Alert, { severity: "error", sx: { mb: 2 }, children: error })), _jsx(TextField, { fullWidth: true, label: "Username", value: credentials.username, onChange: handleChange('username'), margin: "normal", required: true, autoComplete: "username", autoFocus: true }), _jsx(TextField, { fullWidth: true, label: "Password", type: "password", value: credentials.password, onChange: handleChange('password'), margin: "normal", required: true, autoComplete: "current-password" }), _jsx(Button, { type: "submit", fullWidth: true, variant: "contained", sx: { mt: 3, mb: 2 }, disabled: isLoading, children: isLoading ? 'Signing In...' : 'Sign In' })] })] }) }) }));
};
export default Login;
