"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
const material_1 = require("@mui/material");
const AuthContext_1 = require("../contexts/AuthContext");
const Login = () => {
    const [credentials, setCredentials] = (0, react_1.useState)({
        username: '',
        password: '',
    });
    const [error, setError] = (0, react_1.useState)('');
    const [isLoading, setIsLoading] = (0, react_1.useState)(false);
    const { login } = (0, AuthContext_1.useAuth)();
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
    return ((0, jsx_runtime_1.jsx)(material_1.Box, { display: "flex", justifyContent: "center", alignItems: "center", minHeight: "100vh", bgcolor: "background.default", children: (0, jsx_runtime_1.jsx)(material_1.Card, { sx: { maxWidth: 400, width: '100%', mx: 2 }, children: (0, jsx_runtime_1.jsxs)(material_1.CardContent, { sx: { p: 4 }, children: [(0, jsx_runtime_1.jsx)(material_1.Typography, { variant: "h4", component: "h1", gutterBottom: true, align: "center", children: "MCP God Mode" }), (0, jsx_runtime_1.jsx)(material_1.Typography, { variant: "body1", color: "text.secondary", align: "center", gutterBottom: true, children: "Sign in to your account" }), (0, jsx_runtime_1.jsxs)(material_1.Box, { component: "form", onSubmit: handleSubmit, sx: { mt: 3 }, children: [error && ((0, jsx_runtime_1.jsx)(material_1.Alert, { severity: "error", sx: { mb: 2 }, children: error })), (0, jsx_runtime_1.jsx)(material_1.TextField, { fullWidth: true, label: "Username", value: credentials.username, onChange: handleChange('username'), margin: "normal", required: true, autoComplete: "username", autoFocus: true }), (0, jsx_runtime_1.jsx)(material_1.TextField, { fullWidth: true, label: "Password", type: "password", value: credentials.password, onChange: handleChange('password'), margin: "normal", required: true, autoComplete: "current-password" }), (0, jsx_runtime_1.jsx)(material_1.Button, { type: "submit", fullWidth: true, variant: "contained", sx: { mt: 3, mb: 2 }, disabled: isLoading, children: isLoading ? 'Signing In...' : 'Sign In' })] })] }) }) }));
};
exports.default = Login;
