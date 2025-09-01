"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsx_runtime_1 = require("react/jsx-runtime");
const react_1 = require("react");
// Simplified mobile app component that can compile without React Native dependencies
const App = () => {
    const [currentScreen, setCurrentScreen] = (0, react_1.useState)('Dashboard');
    const screens = [
        'Dashboard',
        'Monitoring',
        'Workflows',
        'Plugins',
        'Tools',
        'Settings'
    ];
    return ((0, jsx_runtime_1.jsxs)("div", { style: {
            fontFamily: 'Arial, sans-serif',
            maxWidth: '400px',
            margin: '0 auto',
            padding: '20px',
            backgroundColor: '#f5f5f5',
            minHeight: '100vh'
        }, children: [(0, jsx_runtime_1.jsxs)("header", { style: {
                    textAlign: 'center',
                    padding: '20px 0',
                    borderBottom: '2px solid #007AFF',
                    marginBottom: '20px'
                }, children: [(0, jsx_runtime_1.jsx)("h1", { style: {
                            color: '#007AFF',
                            margin: 0,
                            fontSize: '24px'
                        }, children: "MCP God Mode" }), (0, jsx_runtime_1.jsx)("p", { style: {
                            color: '#666',
                            margin: '10px 0 0 0',
                            fontSize: '14px'
                        }, children: "Mobile Dashboard" })] }), (0, jsx_runtime_1.jsx)("nav", { style: {
                    display: 'flex',
                    flexWrap: 'wrap',
                    gap: '10px',
                    marginBottom: '20px'
                }, children: screens.map(screen => ((0, jsx_runtime_1.jsx)("button", { onClick: () => setCurrentScreen(screen), style: {
                        padding: '10px 15px',
                        border: currentScreen === screen ? '2px solid #007AFF' : '1px solid #ddd',
                        borderRadius: '8px',
                        backgroundColor: currentScreen === screen ? '#007AFF' : 'white',
                        color: currentScreen === screen ? 'white' : '#333',
                        cursor: 'pointer',
                        fontSize: '14px',
                        fontWeight: currentScreen === screen ? 'bold' : 'normal'
                    }, children: screen }, screen))) }), (0, jsx_runtime_1.jsxs)("main", { style: {
                    backgroundColor: 'white',
                    padding: '20px',
                    borderRadius: '12px',
                    boxShadow: '0 2px 10px rgba(0,0,0,0.1)'
                }, children: [(0, jsx_runtime_1.jsx)("h2", { style: {
                            color: '#333',
                            margin: '0 0 20px 0',
                            fontSize: '20px'
                        }, children: currentScreen }), (0, jsx_runtime_1.jsxs)("div", { style: {
                            color: '#666',
                            lineHeight: '1.6'
                        }, children: [currentScreen === 'Dashboard' && ((0, jsx_runtime_1.jsxs)("div", { children: [(0, jsx_runtime_1.jsx)("h3", { children: "System Status" }), (0, jsx_runtime_1.jsx)("p", { children: "All systems operational" }), (0, jsx_runtime_1.jsx)("h3", { children: "Active Tools" }), (0, jsx_runtime_1.jsx)("p", { children: "14 tools available" }), (0, jsx_runtime_1.jsx)("h3", { children: "Recent Activity" }), (0, jsx_runtime_1.jsx)("p", { children: "No recent activity" })] })), currentScreen === 'Monitoring' && ((0, jsx_runtime_1.jsx)("p", { children: "System monitoring dashboard will be implemented here." })), currentScreen === 'Workflows' && ((0, jsx_runtime_1.jsx)("p", { children: "Workflow management will be implemented here." })), currentScreen === 'Plugins' && ((0, jsx_runtime_1.jsx)("p", { children: "Plugin management will be implemented here." })), currentScreen === 'Tools' && ((0, jsx_runtime_1.jsx)("p", { children: "Tool management will be implemented here." })), currentScreen === 'Settings' && ((0, jsx_runtime_1.jsx)("p", { children: "Application settings will be implemented here." }))] })] }), (0, jsx_runtime_1.jsxs)("footer", { style: {
                    textAlign: 'center',
                    padding: '20px 0',
                    color: '#999',
                    fontSize: '12px',
                    marginTop: '20px'
                }, children: [(0, jsx_runtime_1.jsx)("p", { children: "MCP God Mode v1.0.0" }), (0, jsx_runtime_1.jsx)("p", { children: "Cross-platform management interface" })] })] }));
};
exports.default = App;
