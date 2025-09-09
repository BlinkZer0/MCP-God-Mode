"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WebServer = void 0;
const express = require("express");
const http_1 = require("http");
const socket_io_1 = require("socket.io");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const morgan = require("morgan");
const cookieParser = require("cookie-parser");
const path = require("path");
// Import core modules
const security_js_1 = require("./core/security.js");
const monitoring_js_1 = require("./core/monitoring.js");
const automation_js_1 = require("./core/automation.js");
const plugins_js_1 = require("./core/plugins.js");
const defaultWebServerConfig = {
    port: parseInt(process.env.WEB_PORT || '3000'),
    host: process.env.WEB_HOST || 'localhost',
    enableCors: true,
    corsOrigin: process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : ['http://localhost:3000', 'http://localhost:3001'],
    enableCompression: true,
    enableLogging: true,
    staticPath: './public',
    apiPrefix: '/api/v1'
};
// Web server class
class WebServer {
    app;
    server;
    io;
    config;
    // Core services
    authService;
    rateLimiter;
    auditLogger;
    systemMonitor;
    workflowEngine;
    pluginManager;
    constructor(config = defaultWebServerConfig) {
        this.config = config;
        // Initialize core services
        this.authService = new security_js_1.AuthService(security_js_1.defaultSecurityConfig);
        this.rateLimiter = new security_js_1.RateLimiter(security_js_1.defaultSecurityConfig);
        this.auditLogger = new security_js_1.AuditLogger();
        this.systemMonitor = new monitoring_js_1.SystemMonitor(monitoring_js_1.defaultMonitoringConfig);
        this.workflowEngine = new automation_js_1.WorkflowEngine();
        this.pluginManager = new plugins_js_1.PluginManager(plugins_js_1.defaultPluginConfig);
        // Initialize Express app
        this.app = express();
        this.server = (0, http_1.createServer)(this.app);
        this.io = new socket_io_1.Server(this.server, {
            cors: {
                origin: config.corsOrigin,
                methods: ['GET', 'POST']
            }
        });
        this.setupMiddleware();
        this.setupRoutes();
        this.setupWebSocket();
        this.setupErrorHandling();
    }
    setupMiddleware() {
        // Security middleware
        this.app.use(helmet.default({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrc: ["'self'"],
                    imgSrc: ["'self'", "data:", "https:"],
                },
            },
        }));
        // CORS
        if (this.config.enableCors) {
            this.app.use(cors({
                origin: this.config.corsOrigin,
                credentials: true
            }));
        }
        // Compression
        if (this.config.enableCompression) {
            this.app.use(compression());
        }
        // Body parsing
        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
        this.app.use(cookieParser());
        // Logging
        if (this.config.enableLogging) {
            this.app.use(morgan('combined'));
        }
        // Rate limiting
        this.app.use((0, security_js_1.rateLimitMiddleware)(this.rateLimiter));
        // Static files
        this.app.use(express.static(path.resolve(this.config.staticPath)));
    }
    setupRoutes() {
        // Health check
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                services: {
                    auth: 'active',
                    monitoring: 'active',
                    workflow: 'active',
                    plugins: 'active'
                }
            });
        });
        // API routes
        this.app.use(`${this.config.apiPrefix}/auth`, this.createAuthRoutes());
        this.app.use(`${this.config.apiPrefix}/system`, this.createSystemRoutes());
        this.app.use(`${this.config.apiPrefix}/monitoring`, this.createMonitoringRoutes());
        this.app.use(`${this.config.apiPrefix}/workflows`, this.createWorkflowRoutes());
        this.app.use(`${this.config.apiPrefix}/plugins`, this.createPluginRoutes());
        this.app.use(`${this.config.apiPrefix}/tools`, this.createToolRoutes());
        // Dashboard route (SPA)
        this.app.get('*', (req, res) => {
            res.sendFile(path.resolve(this.config.staticPath, 'index.html'));
        });
    }
    createAuthRoutes() {
        const router = express.Router();
        // Login
        router.post('/login', async (req, res) => {
            try {
                const { username, password } = req.body;
                if (!username || !password) {
                    return res.status(400).json({ error: 'Username and password are required' });
                }
                const authResult = await this.authService.authenticate(username, password);
                if (!authResult) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }
                const { user, token } = authResult;
                const sessionId = await this.authService.createSession(user.id);
                // Set session cookie (commented out due to cookie-parser dependency)
                // res.cookie('sessionId', sessionId, {
                //   httpOnly: true,
                //   secure: process.env.NODE_ENV === 'production',
                //   maxAge: 24 * 60 * 60 * 1000 // 24 hours
                // });
                res.json({
                    user: {
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        role: user.role,
                        permissions: user.permissions
                    },
                    token
                });
                this.auditLogger.logAction(user, 'login', 'auth', { ip: req.ip });
            }
            catch (error) {
                res.status(500).json({ error: 'Authentication failed' });
            }
        });
        // Logout
        router.post('/logout', (0, security_js_1.authMiddleware)(this.authService), (req, res) => {
            // res.clearCookie('sessionId');
            res.json({ message: 'Logged out successfully' });
            if (req.user) {
                this.auditLogger.logAction(req.user, 'logout', 'auth', { ip: req.ip });
            }
        });
        // Get current user
        router.get('/me', (0, security_js_1.authMiddleware)(this.authService), (req, res) => {
            res.json({
                id: req.user.id,
                username: req.user.username,
                email: req.user.email,
                role: req.user.role,
                permissions: req.user.permissions
            });
        });
        // Create user (admin only)
        router.post('/users', (0, security_js_1.authMiddleware)(this.authService), (0, security_js_1.permissionMiddleware)('users', 'write'), async (req, res) => {
            try {
                const { username, email, password, role } = req.body;
                if (!username || !email || !password) {
                    return res.status(400).json({ error: 'Username, email, and password are required' });
                }
                const user = await this.authService.createUser(username, email, password, role);
                res.status(201).json({
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                });
                this.auditLogger.logAction(req.user, 'create_user', 'users', { createdUser: username });
            }
            catch (error) {
                res.status(500).json({ error: 'Failed to create user' });
            }
        });
        return router;
    }
    createSystemRoutes() {
        const router = express.Router();
        // Get system information
        router.get('/info', (0, security_js_1.authMiddleware)(this.authService), (req, res) => {
            const systemInfo = {
                platform: process.platform,
                arch: process.arch,
                nodeVersion: process.version,
                uptime: process.uptime(),
                memoryUsage: process.memoryUsage(),
                cpuUsage: process.cpuUsage(),
                version: process.env.npm_package_version || '1.0.0'
            };
            res.json(systemInfo);
            if (req.user) {
                this.auditLogger.logAction(req.user, 'get_system_info', 'system', {});
            }
        });
        // Get system status
        router.get('/status', (0, security_js_1.authMiddleware)(this.authService), (req, res) => {
            const status = {
                timestamp: new Date().toISOString(),
                services: {
                    auth: 'active',
                    monitoring: 'active',
                    workflow: 'active',
                    plugins: 'active'
                },
                metrics: this.systemMonitor.getLatestMetrics(),
                alerts: this.systemMonitor.getAlerts(false).slice(0, 10)
            };
            res.json(status);
        });
        return router;
    }
    createMonitoringRoutes() {
        const router = express.Router();
        // Get current metrics
        router.get('/metrics/current', (0, security_js_1.authMiddleware)(this.authService), (req, res) => {
            const metrics = this.systemMonitor.getLatestMetrics();
            res.json(metrics || { error: 'No metrics available' });
        });
        // Get metrics history
        router.get('/metrics/history', (0, security_js_1.authMiddleware)(this.authService), (req, res) => {
            const limit = parseInt(req.query.limit) || 100;
            const metrics = this.systemMonitor.getMetricsHistory(limit);
            res.json(metrics);
        });
        // Get alerts
        router.get('/alerts', (0, security_js_1.authMiddleware)(this.authService), (req, res) => {
            const acknowledged = req.query.acknowledged === 'true';
            const alerts = this.systemMonitor.getAlerts(acknowledged);
            res.json(alerts);
        });
        // Acknowledge alert
        router.post('/alerts/:alertId/acknowledge', (0, security_js_1.authMiddleware)(this.authService), (0, security_js_1.permissionMiddleware)('monitoring', 'write'), (req, res) => {
            const { alertId } = req.params;
            const success = this.systemMonitor.acknowledgeAlert(alertId, req.user.username);
            if (success) {
                res.json({ message: 'Alert acknowledged' });
                this.auditLogger.logAction(req.user, 'acknowledge_alert', 'monitoring', { alertId });
            }
            else {
                res.status(404).json({ error: 'Alert not found' });
            }
        });
        // Get performance baselines
        router.get('/baselines', (0, security_js_1.authMiddleware)(this.authService), (req, res) => {
            const baselines = this.systemMonitor.getBaselines();
            res.json(baselines);
        });
        return router;
    }
    createWorkflowRoutes() {
        const router = express.Router();
        // Get all workflows
        router.get('/', (0, security_js_1.authMiddleware)(this.authService), (req, res) => {
            const workflows = this.workflowEngine.getAllWorkflows();
            res.json(workflows);
        });
        // Get workflow by ID
        router.get('/:workflowId', (0, security_js_1.authMiddleware)(this.authService), (req, res) => {
            const workflow = this.workflowEngine.getWorkflow(req.params.workflowId);
            if (workflow) {
                res.json(workflow);
            }
            else {
                res.status(404).json({ error: 'Workflow not found' });
            }
        });
        // Create workflow
        router.post('/', (0, security_js_1.authMiddleware)(this.authService), (0, security_js_1.permissionMiddleware)('workflows', 'write'), async (req, res) => {
            try {
                const workflowData = { ...req.body, createdBy: req.user.username };
                const workflow = await this.workflowEngine.createWorkflow(workflowData);
                res.status(201).json(workflow);
                this.auditLogger.logAction(req.user, 'create_workflow', 'workflows', { workflowId: workflow.id });
            }
            catch (error) {
                res.status(400).json({ error: 'Failed to create workflow' });
            }
        });
        // Execute workflow
        router.post('/:workflowId/execute', (0, security_js_1.authMiddleware)(this.authService), (0, security_js_1.permissionMiddleware)('workflows', 'execute'), async (req, res) => {
            try {
                const { workflowId } = req.params;
                const { variables } = req.body;
                const executionId = await this.workflowEngine.executeWorkflow(workflowId, variables, req.user.username);
                res.json({ executionId });
                this.auditLogger.logAction(req.user, 'execute_workflow', 'workflows', { workflowId, executionId });
            }
            catch (error) {
                res.status(400).json({ error: 'Failed to execute workflow' });
            }
        });
        // Get workflow executions
        router.get('/:workflowId/executions', (0, security_js_1.authMiddleware)(this.authService), (req, res) => {
            const executions = this.workflowEngine.getAllExecutions();
            const workflowExecutions = executions.filter(e => e.workflowId === req.params.workflowId);
            res.json(workflowExecutions);
        });
        // Get scheduled tasks
        router.get('/scheduled-tasks', (0, security_js_1.authMiddleware)(this.authService), (req, res) => {
            const tasks = this.workflowEngine.getAllScheduledTasks();
            res.json(tasks);
        });
        return router;
    }
    createPluginRoutes() {
        const router = express.Router();
        // Get all plugins
        router.get('/', (0, security_js_1.authMiddleware)(this.authService), (req, res) => {
            const plugins = this.pluginManager.getAllPlugins();
            res.json(plugins);
        });
        // Get plugin by ID
        router.get('/:pluginId', (0, security_js_1.authMiddleware)(this.authService), (req, res) => {
            const plugin = this.pluginManager.getPlugin(req.params.pluginId);
            if (plugin) {
                res.json(plugin);
            }
            else {
                res.status(404).json({ error: 'Plugin not found' });
            }
        });
        // Load plugin
        router.post('/:pluginId/load', (0, security_js_1.authMiddleware)(this.authService), (0, security_js_1.permissionMiddleware)('plugins', 'write'), async (req, res) => {
            try {
                const plugin = await this.pluginManager.loadPlugin(req.params.pluginId);
                if (plugin) {
                    res.json(plugin);
                    this.auditLogger.logAction(req.user, 'load_plugin', 'plugins', { pluginId: plugin.id });
                }
                else {
                    res.status(500).json({ error: 'Failed to load plugin' });
                }
            }
            catch (error) {
                res.status(500).json({ error: 'Failed to load plugin' });
            }
        });
        // Unload plugin
        router.post('/:pluginId/unload', (0, security_js_1.authMiddleware)(this.authService), (0, security_js_1.permissionMiddleware)('plugins', 'write'), async (req, res) => {
            try {
                const success = await this.pluginManager.unloadPlugin(req.params.pluginId);
                if (success) {
                    res.json({ message: 'Plugin unloaded' });
                    this.auditLogger.logAction(req.user, 'unload_plugin', 'plugins', { pluginId: req.params.pluginId });
                }
                else {
                    res.status(404).json({ error: 'Plugin not found' });
                }
            }
            catch (error) {
                res.status(500).json({ error: 'Failed to unload plugin' });
            }
        });
        // Enable/disable plugin
        router.post('/:pluginId/:action', (0, security_js_1.authMiddleware)(this.authService), (0, security_js_1.permissionMiddleware)('plugins', 'write'), async (req, res) => {
            try {
                const { pluginId, action } = req.params;
                let success = false;
                if (action === 'enable') {
                    success = await this.pluginManager.enablePlugin(pluginId);
                }
                else if (action === 'disable') {
                    success = await this.pluginManager.disablePlugin(pluginId);
                }
                else {
                    return res.status(400).json({ error: 'Invalid action' });
                }
                if (success) {
                    res.json({ message: `Plugin ${action}d` });
                    this.auditLogger.logAction(req.user, `${action}_plugin`, 'plugins', { pluginId });
                }
                else {
                    res.status(404).json({ error: 'Plugin not found' });
                }
            }
            catch (error) {
                res.status(500).json({ error: 'Failed to modify plugin' });
            }
        });
        // Get plugin tools
        router.get('/:pluginId/tools', (0, security_js_1.authMiddleware)(this.authService), (req, res) => {
            const tools = this.pluginManager.getPluginTools(req.params.pluginId);
            res.json(tools);
        });
        // Execute plugin tool
        router.post('/:pluginId/tools/:toolId', (0, security_js_1.authMiddleware)(this.authService), (0, security_js_1.permissionMiddleware)('plugins', 'execute'), async (req, res) => {
            try {
                const { pluginId, toolId } = req.params;
                const result = await this.pluginManager.executePluginTool(pluginId, toolId, req.body);
                res.json(result);
                this.auditLogger.logAction(req.user, 'execute_plugin_tool', 'plugins', { pluginId, toolId });
            }
            catch (error) {
                res.status(500).json({ error: 'Failed to execute plugin tool' });
            }
        });
        return router;
    }
    createToolRoutes() {
        const router = express.Router();
        // Get all available tools (including plugin tools)
        router.get('/', (0, security_js_1.authMiddleware)(this.authService), (req, res) => {
            const mcpTools = [
                // This would be populated with your actual MCP tools
                { id: 'health', name: 'Health Check', category: 'system' },
                { id: 'system_info', name: 'System Information', category: 'system' },
                { id: 'vm_management', name: 'VM Management', category: 'virtualization' },
                { id: 'docker_management', name: 'Docker Management', category: 'containers' }
            ];
            const pluginTools = this.pluginManager.getAllPluginTools();
            res.json({
                mcp: mcpTools,
                plugins: pluginTools
            });
        });
        return router;
    }
    setupWebSocket() {
        this.io.on('connection', (socket) => {
            console.log('Client connected:', socket.id);
            // Join monitoring room
            socket.join('monitoring');
            // Handle disconnection
            socket.on('disconnect', () => {
                console.log('Client disconnected:', socket.id);
            });
        });
        // Emit real-time updates
        this.systemMonitor.on('metrics', (metrics) => {
            this.io.to('monitoring').emit('metrics', metrics);
        });
        this.systemMonitor.on('alert', (alert) => {
            this.io.to('monitoring').emit('alert', alert);
        });
        this.workflowEngine.on('workflowCompleted', (execution) => {
            this.io.emit('workflowCompleted', execution);
        });
    }
    setupErrorHandling() {
        // 404 handler
        this.app.use((req, res, next) => {
            res.status(404).json({ error: 'Not found' });
        });
        // Global error handler
        this.app.use((error, req, res, next) => {
            console.error('Global error:', error);
            res.status(500).json({ error: 'Internal server error' });
        });
    }
    // Start the server
    async start() {
        try {
            // Load plugins
            await this.pluginManager.loadAllPlugins();
            // Start monitoring
            this.systemMonitor.on('metrics', (metrics) => {
                console.log('Metrics collected:', new Date().toISOString());
            });
            this.systemMonitor.on('alert', (alert) => {
                console.log('Alert triggered:', alert.message);
            });
            // Start server
            this.server.listen(this.config.port, this.config.host, () => {
                console.log(`🚀 MCP God Mode Web Server running on http://${this.config.host}:${this.config.port}`);
                console.log(`📊 Dashboard available at http://${this.config.host}:${this.config.port}`);
                console.log(`🔌 API available at http://${this.config.host}:${this.config.port}${this.config.apiPrefix}`);
            });
        }
        catch (error) {
            console.error('Failed to start web server:', error);
            process.exit(1);
        }
    }
    // Stop the server
    async stop() {
        try {
            // Stop monitoring
            this.systemMonitor.stop();
            // Stop workflow engine
            this.workflowEngine.stop();
            // Cleanup plugins
            await this.pluginManager.cleanup();
            // Close server
            this.server.close(() => {
                console.log('Web server stopped');
            });
        }
        catch (error) {
            console.error('Error stopping web server:', error);
        }
    }
}
exports.WebServer = WebServer;
// Start server if this file is run directly
if (process.argv[1] && process.argv[1].endsWith('web-server.js')) {
    const server = new WebServer();
    process.on('SIGINT', async () => {
        console.log('\nShutting down...');
        await server.stop();
        process.exit(0);
    });
    process.on('SIGTERM', async () => {
        console.log('\nShutting down...');
        await server.stop();
        process.exit(0);
    });
    server.start();
}
