#!/usr/bin/env node
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MCPGodModeCLI = void 0;
const commander_1 = require("commander");
const inquirer_1 = __importDefault(require("inquirer"));
const ora_1 = __importDefault(require("ora"));
const chalk_1 = __importDefault(require("chalk"));
const web_server_js_1 = require("./web-server.js");
const monitoring_js_1 = require("./core/monitoring.js");
const automation_js_1 = require("./core/automation.js");
const plugins_js_1 = require("./core/plugins.js");
const security_js_1 = require("./core/security.js");
const defaultCLIConfig = {
    enableColors: true,
    enableSpinners: true,
    defaultTimeout: 30000,
    logLevel: 'info'
};
// CLI class
class MCPGodModeCLI {
    program;
    config;
    spinner = null;
    // Core services
    systemMonitor;
    workflowEngine;
    pluginManager;
    authService;
    constructor(config = defaultCLIConfig) {
        this.config = config;
        // Initialize core services
        this.systemMonitor = new monitoring_js_1.SystemMonitor(monitoring_js_1.defaultMonitoringConfig);
        this.workflowEngine = new automation_js_1.WorkflowEngine();
        this.pluginManager = new plugins_js_1.PluginManager(plugins_js_1.defaultPluginConfig);
        this.authService = new security_js_1.AuthService(security_js_1.defaultSecurityConfig);
        // Initialize CLI program
        this.program = new commander_1.Command();
        this.setupCLI();
    }
    setupCLI() {
        this.program
            .name('mcp-god-mode')
            .description('MCP God Mode - Ultimate System Management CLI')
            .version('1.0.0');
        // Global options
        this.program
            .option('-c, --config <path>', 'Path to configuration file')
            .option('-v, --verbose', 'Enable verbose logging')
            .option('--no-color', 'Disable colored output')
            .option('--no-spinner', 'Disable loading spinners');
        // System commands
        this.setupSystemCommands();
        // Monitoring commands
        this.setupMonitoringCommands();
        // Workflow commands
        this.setupWorkflowCommands();
        // Plugin commands
        this.setupPluginCommands();
        // Web server commands
        this.setupWebServerCommands();
        // Interactive mode
        this.setupInteractiveMode();
    }
    setupSystemCommands() {
        const systemGroup = this.program
            .command('system')
            .description('System management commands');
        // System info
        systemGroup
            .command('info')
            .description('Display system information')
            .action(async () => {
            await this.showSystemInfo();
        });
        // System health
        systemGroup
            .command('health')
            .description('Check system health')
            .action(async () => {
            await this.checkSystemHealth();
        });
        // System status
        systemGroup
            .command('status')
            .description('Show system status')
            .action(async () => {
            await this.showSystemStatus();
        });
    }
    setupMonitoringCommands() {
        const monitoringGroup = this.program
            .command('monitoring')
            .description('System monitoring commands');
        // Current metrics
        monitoringGroup
            .command('metrics')
            .description('Show current system metrics')
            .option('-h, --history <count>', 'Show historical metrics', '10')
            .action(async (options) => {
            await this.showMetrics(parseInt(options.history));
        });
        // Alerts
        monitoringGroup
            .command('alerts')
            .description('Show system alerts')
            .option('-a, --acknowledged', 'Show acknowledged alerts')
            .action(async (options) => {
            await this.showAlerts(options.acknowledged);
        });
        // Baselines
        monitoringGroup
            .command('baselines')
            .description('Show performance baselines')
            .action(async () => {
            await this.showBaselines();
        });
    }
    setupWorkflowCommands() {
        const workflowGroup = this.program
            .command('workflow')
            .description('Workflow automation commands');
        // List workflows
        workflowGroup
            .command('list')
            .description('List all workflows')
            .action(async () => {
            await this.listWorkflows();
        });
        // Show workflow
        workflowGroup
            .command('show <id>')
            .description('Show workflow details')
            .action(async (id) => {
            await this.showWorkflow(id);
        });
        // Execute workflow
        workflowGroup
            .command('execute <id>')
            .description('Execute a workflow')
            .option('-v, --variables <json>', 'Workflow variables as JSON')
            .action(async (id, options) => {
            await this.executeWorkflow(id, options.variables);
        });
        // Create workflow
        workflowGroup
            .command('create')
            .description('Create a new workflow')
            .action(async () => {
            await this.createWorkflow();
        });
        // Scheduled tasks
        workflowGroup
            .command('scheduled')
            .description('Show scheduled tasks')
            .action(async () => {
            await this.showScheduledTasks();
        });
    }
    setupPluginCommands() {
        const pluginGroup = this.program
            .command('plugin')
            .description('Plugin management commands');
        // List plugins
        pluginGroup
            .command('list')
            .description('List all plugins')
            .action(async () => {
            await this.listPlugins();
        });
        // Show plugin
        pluginGroup
            .command('show <id>')
            .description('Show plugin details')
            .action(async (id) => {
            await this.showPlugin(id);
        });
        // Load plugin
        pluginGroup
            .command('load <id>')
            .description('Load a plugin')
            .action(async (id) => {
            await this.loadPlugin(id);
        });
        // Unload plugin
        pluginGroup
            .command('unload <id>')
            .description('Unload a plugin')
            .action(async (id) => {
            await this.unloadPlugin(id);
        });
        // Enable/disable plugin
        pluginGroup
            .command('toggle <id>')
            .description('Enable or disable a plugin')
            .action(async (id) => {
            await this.togglePlugin(id);
        });
        // Plugin tools
        pluginGroup
            .command('tools <id>')
            .description('Show plugin tools')
            .action(async (id) => {
            await this.showPluginTools(id);
        });
    }
    setupWebServerCommands() {
        const webGroup = this.program
            .command('web')
            .description('Web server commands');
        // Start web server
        webGroup
            .command('start')
            .description('Start the web server')
            .option('-p, --port <port>', 'Port number', '3000')
            .option('-h, --host <host>', 'Host address', 'localhost')
            .action(async (options) => {
            await this.startWebServer(parseInt(options.port), options.host);
        });
        // Stop web server
        webGroup
            .command('stop')
            .description('Stop the web server')
            .action(async () => {
            await this.stopWebServer();
        });
        // Status
        webGroup
            .command('status')
            .description('Show web server status')
            .action(async () => {
            await this.showWebServerStatus();
        });
    }
    setupInteractiveMode() {
        this.program
            .command('interactive')
            .alias('i')
            .description('Start interactive mode')
            .action(async () => {
            await this.startInteractiveMode();
        });
    }
    // Command implementations
    async showSystemInfo() {
        this.startSpinner('Gathering system information...');
        try {
            const info = {
                platform: process.platform,
                arch: process.arch,
                nodeVersion: process.version,
                uptime: process.uptime(),
                memoryUsage: process.memoryUsage(),
                version: '1.0.0'
            };
            this.stopSpinner();
            console.log(chalk_1.default.blue.bold('\n🖥️  System Information'));
            console.log(chalk_1.default.gray('─'.repeat(50)));
            console.log(chalk_1.default.cyan('Platform:'), info.platform);
            console.log(chalk_1.default.cyan('Architecture:'), info.arch);
            console.log(chalk_1.default.cyan('Node.js Version:'), info.nodeVersion);
            console.log(chalk_1.default.cyan('Uptime:'), `${Math.floor(info.uptime / 3600)}h ${Math.floor((info.uptime % 3600) / 60)}m`);
            console.log(chalk_1.default.cyan('Memory Usage:'), `${Math.round(info.memoryUsage.heapUsed / 1024 / 1024)}MB`);
            console.log(chalk_1.default.cyan('Version:'), info.version);
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to get system information:'), error);
        }
    }
    async checkSystemHealth() {
        this.startSpinner('Checking system health...');
        try {
            const metrics = this.systemMonitor.getLatestMetrics();
            this.stopSpinner();
            if (!metrics) {
                console.log(chalk_1.default.yellow('No metrics available'));
                return;
            }
            console.log(chalk_1.default.blue.bold('\n🏥 System Health Check'));
            console.log(chalk_1.default.gray('─'.repeat(50)));
            // CPU health
            const cpuHealth = metrics.cpu.usage < 70 ? '🟢' : metrics.cpu.usage < 90 ? '🟡' : '🔴';
            console.log(`${cpuHealth} CPU Usage: ${metrics.cpu.usage.toFixed(1)}%`);
            // Memory health
            const memHealth = metrics.memory.usage < 80 ? '🟢' : metrics.memory.usage < 95 ? '🟡' : '🔴';
            console.log(`${memHealth} Memory Usage: ${metrics.memory.usage.toFixed(1)}%`);
            // Disk health
            const diskHealth = metrics.disk.usage < 85 ? '🟢' : metrics.disk.usage < 95 ? '🟡' : '🔴';
            console.log(`${diskHealth} Disk Usage: ${metrics.disk.usage.toFixed(1)}%`);
            // Overall health
            const overallHealth = (metrics.cpu.usage < 70 && metrics.memory.usage < 80 && metrics.disk.usage < 85) ? '🟢' : '🟡';
            console.log(chalk_1.default.gray('─'.repeat(50)));
            console.log(`${overallHealth} Overall Health: ${overallHealth === '🟢' ? 'Good' : 'Warning'}`);
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to check system health:'), error);
        }
    }
    async showSystemStatus() {
        this.startSpinner('Getting system status...');
        try {
            const status = {
                timestamp: new Date().toISOString(),
                services: {
                    auth: 'active',
                    monitoring: 'active',
                    workflow: 'active',
                    plugins: 'active'
                },
                metrics: this.systemMonitor.getLatestMetrics(),
                alerts: this.systemMonitor.getAlerts(false).slice(0, 5)
            };
            this.stopSpinner();
            console.log(chalk_1.default.blue.bold('\n📊 System Status'));
            console.log(chalk_1.default.gray('─'.repeat(50)));
            console.log(chalk_1.default.cyan('Timestamp:'), new Date(status.timestamp).toLocaleString());
            console.log(chalk_1.default.cyan('Services:'), Object.entries(status.services).map(([k, v]) => `${k}: ${v}`).join(', '));
            if (status.metrics) {
                console.log(chalk_1.default.cyan('Current CPU:'), `${status.metrics.cpu.usage.toFixed(1)}%`);
                console.log(chalk_1.default.cyan('Current Memory:'), `${status.metrics.memory.usage.toFixed(1)}%`);
            }
            if (status.alerts.length > 0) {
                console.log(chalk_1.default.cyan('Active Alerts:'), status.alerts.length);
                status.alerts.forEach(alert => {
                    const level = alert.level === 'critical' ? '🔴' : alert.level === 'warning' ? '🟡' : '🔵';
                    console.log(`  ${level} ${alert.message}`);
                });
            }
            else {
                console.log(chalk_1.default.cyan('Active Alerts:'), 'None');
            }
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to get system status:'), error);
        }
    }
    async showMetrics(historyCount) {
        this.startSpinner('Getting metrics...');
        try {
            const metrics = this.systemMonitor.getMetricsHistory(historyCount);
            this.stopSpinner();
            if (metrics.length === 0) {
                console.log(chalk_1.default.yellow('No metrics available'));
                return;
            }
            console.log(chalk_1.default.blue.bold(`\n📈 System Metrics (Last ${metrics.length} samples)`));
            console.log(chalk_1.default.gray('─'.repeat(80)));
            // Show latest metrics
            const latest = metrics[metrics.length - 1];
            console.log(chalk_1.default.cyan('Latest Sample:'), new Date(latest.timestamp).toLocaleString());
            console.log(chalk_1.default.cyan('CPU Usage:'), `${latest.cpu.usage.toFixed(1)}%`);
            console.log(chalk_1.default.cyan('Memory Usage:'), `${latest.memory.usage.toFixed(1)}%`);
            console.log(chalk_1.default.cyan('Disk Usage:'), `${latest.disk.usage.toFixed(1)}%`);
            // Show trend
            if (metrics.length > 1) {
                const first = metrics[0];
                const cpuTrend = latest.cpu.usage > first.cpu.usage ? '↗️' : latest.cpu.usage < first.cpu.usage ? '↘️' : '→';
                const memTrend = latest.memory.usage > first.memory.usage ? '↗️' : latest.memory.usage < first.memory.usage ? '↘️' : '→';
                console.log(chalk_1.default.gray('─'.repeat(80)));
                console.log(chalk_1.default.cyan('Trends:'), `CPU: ${cpuTrend} Memory: ${memTrend}`);
            }
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to get metrics:'), error);
        }
    }
    async showAlerts(acknowledged = false) {
        this.startSpinner('Getting alerts...');
        try {
            const alerts = this.systemMonitor.getAlerts(acknowledged);
            this.stopSpinner();
            if (alerts.length === 0) {
                console.log(chalk_1.default.yellow(`No ${acknowledged ? 'acknowledged' : 'active'} alerts`));
                return;
            }
            console.log(chalk_1.default.blue.bold(`\n🚨 System Alerts (${acknowledged ? 'Acknowledged' : 'Active'})`));
            console.log(chalk_1.default.gray('─'.repeat(100)));
            alerts.forEach(alert => {
                const level = alert.level === 'critical' ? '🔴' : alert.level === 'warning' ? '🟡' : '🔵';
                const status = alert.acknowledged ? '✅' : '⏳';
                const time = new Date(alert.timestamp).toLocaleString();
                console.log(`${level} ${status} ${alert.message}`);
                console.log(`   Resource: ${alert.resource} | Value: ${alert.value} | Threshold: ${alert.threshold}`);
                console.log(`   Time: ${time}`);
                if (alert.acknowledged) {
                    console.log(`   Acknowledged by: ${alert.acknowledgedBy} at ${alert.acknowledgedAt?.toLocaleString()}`);
                }
                console.log('');
            });
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to get alerts:'), error);
        }
    }
    async showBaselines() {
        this.startSpinner('Getting performance baselines...');
        try {
            const baselines = this.systemMonitor.getBaselines();
            this.stopSpinner();
            if (baselines.length === 0) {
                console.log(chalk_1.default.yellow('No performance baselines available'));
                return;
            }
            console.log(chalk_1.default.blue.bold('\n📊 Performance Baselines'));
            console.log(chalk_1.default.gray('─'.repeat(80)));
            baselines.forEach(baseline => {
                console.log(chalk_1.default.cyan(`${baseline.resource}.${baseline.metric}:`));
                console.log(`   Average: ${baseline.avg.toFixed(2)}`);
                console.log(`   Range: ${baseline.min.toFixed(2)} - ${baseline.max.toFixed(2)}`);
                console.log(`   Std Dev: ${baseline.stdDev.toFixed(2)}`);
                console.log(`   Samples: ${baseline.samples}`);
                console.log(`   Updated: ${baseline.lastUpdated.toLocaleString()}`);
                console.log('');
            });
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to get baselines:'), error);
        }
    }
    async listWorkflows() {
        this.startSpinner('Getting workflows...');
        try {
            const workflows = this.workflowEngine.getAllWorkflows();
            this.stopSpinner();
            if (workflows.length === 0) {
                console.log(chalk_1.default.yellow('No workflows available'));
                return;
            }
            console.log(chalk_1.default.blue.bold('\n🔄 Available Workflows'));
            console.log(chalk_1.default.gray('─'.repeat(80)));
            workflows.forEach(workflow => {
                const status = workflow.enabled ? '🟢' : '🔴';
                const steps = workflow.steps.length;
                const triggers = workflow.triggers.length;
                console.log(`${status} ${chalk_1.default.cyan(workflow.name)} (${workflow.id})`);
                console.log(`   Description: ${workflow.description}`);
                console.log(`   Version: ${workflow.version}`);
                console.log(`   Steps: ${steps} | Triggers: ${triggers}`);
                console.log(`   Created: ${workflow.createdAt.toLocaleDateString()}`);
                console.log(`   Status: ${workflow.enabled ? 'Enabled' : 'Disabled'}`);
                console.log('');
            });
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to get workflows:'), error);
        }
    }
    async showWorkflow(id) {
        this.startSpinner('Getting workflow details...');
        try {
            const workflow = this.workflowEngine.getWorkflow(id);
            this.stopSpinner();
            if (!workflow) {
                console.log(chalk_1.default.red(`Workflow not found: ${id}`));
                return;
            }
            console.log(chalk_1.default.blue.bold(`\n🔄 Workflow: ${workflow.name}`));
            console.log(chalk_1.default.gray('─'.repeat(80)));
            console.log(chalk_1.default.cyan('ID:'), workflow.id);
            console.log(chalk_1.default.cyan('Description:'), workflow.description);
            console.log(chalk_1.default.cyan('Version:'), workflow.version);
            console.log(chalk_1.default.cyan('Status:'), workflow.enabled ? '🟢 Enabled' : '🔴 Disabled');
            console.log(chalk_1.default.cyan('Created:'), workflow.createdAt.toLocaleDateString());
            console.log(chalk_1.default.cyan('Created By:'), workflow.createdBy);
            console.log(chalk_1.default.gray('─'.repeat(80)));
            console.log(chalk_1.default.cyan('Steps:'));
            workflow.steps.forEach((step, index) => {
                console.log(`   ${index + 1}. ${step.name} (${step.type})`);
                if (step.nextStepId) {
                    console.log(`      → Next: ${step.nextStepId}`);
                }
            });
            if (workflow.triggers.length > 0) {
                console.log(chalk_1.default.gray('─'.repeat(80)));
                console.log(chalk_1.default.cyan('Triggers:'));
                workflow.triggers.forEach(trigger => {
                    const status = trigger.enabled ? '🟢' : '🔴';
                    console.log(`   ${status} ${trigger.type}: ${JSON.stringify(trigger.config)}`);
                });
            }
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to get workflow details:'), error);
        }
    }
    async executeWorkflow(id, variablesJson) {
        this.startSpinner('Executing workflow...');
        try {
            let variables = {};
            if (variablesJson) {
                try {
                    variables = JSON.parse(variablesJson);
                }
                catch (error) {
                    this.stopSpinner();
                    console.error(chalk_1.default.red('Invalid JSON for variables'));
                    return;
                }
            }
            const executionId = await this.workflowEngine.executeWorkflow(id, variables, 'cli-user');
            this.stopSpinner();
            console.log(chalk_1.default.green.bold('\n✅ Workflow execution started'));
            console.log(chalk_1.default.cyan('Execution ID:'), executionId);
            console.log(chalk_1.default.cyan('Workflow ID:'), id);
            console.log(chalk_1.default.cyan('Variables:'), JSON.stringify(variables, null, 2));
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to execute workflow:'), error);
        }
    }
    async createWorkflow() {
        try {
            const answers = await inquirer_1.default.prompt([
                {
                    type: 'input',
                    name: 'name',
                    message: 'Workflow name:',
                    validate: (input) => input.length > 0 ? true : 'Name is required'
                },
                {
                    type: 'input',
                    name: 'description',
                    message: 'Workflow description:',
                    default: ''
                },
                {
                    type: 'input',
                    name: 'version',
                    message: 'Version:',
                    default: '1.0.0'
                }
            ]);
            this.startSpinner('Creating workflow...');
            const workflow = await this.workflowEngine.createWorkflow({
                ...answers,
                steps: [],
                conditions: [],
                variables: {},
                triggers: [],
                enabled: true,
                createdBy: 'cli-user'
            });
            this.stopSpinner();
            console.log(chalk_1.default.green.bold('\n✅ Workflow created successfully'));
            console.log(chalk_1.default.cyan('ID:'), workflow.id);
            console.log(chalk_1.default.cyan('Name:'), workflow.name);
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to create workflow:'), error);
        }
    }
    async showScheduledTasks() {
        this.startSpinner('Getting scheduled tasks...');
        try {
            const tasks = this.workflowEngine.getAllScheduledTasks();
            this.stopSpinner();
            if (tasks.length === 0) {
                console.log(chalk_1.default.yellow('No scheduled tasks available'));
                return;
            }
            console.log(chalk_1.default.blue.bold('\n⏰ Scheduled Tasks'));
            console.log(chalk_1.default.gray('─'.repeat(80)));
            tasks.forEach(task => {
                const status = task.enabled ? '🟢' : '🔴';
                const nextRun = task.nextRun ? task.nextRun.toLocaleString() : 'Unknown';
                console.log(`${status} ${chalk_1.default.cyan(task.name)} (${task.id})`);
                console.log(`   Description: ${task.description}`);
                console.log(`   Schedule: ${task.cronExpression}`);
                console.log(`   Next Run: ${nextRun}`);
                console.log(`   Last Run: ${task.lastRun ? task.lastRun.toLocaleString() : 'Never'}`);
                console.log(`   Run Count: ${task.runCount}`);
                console.log(`   Status: ${task.enabled ? 'Enabled' : 'Disabled'}`);
                console.log('');
            });
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to get scheduled tasks:'), error);
        }
    }
    async listPlugins() {
        this.startSpinner('Getting plugins...');
        try {
            const plugins = this.pluginManager.getAllPlugins();
            this.stopSpinner();
            if (plugins.length === 0) {
                console.log(chalk_1.default.yellow('No plugins available'));
                return;
            }
            console.log(chalk_1.default.blue.bold('\n🔌 Available Plugins'));
            console.log(chalk_1.default.gray('─'.repeat(80)));
            plugins.forEach(plugin => {
                const status = plugin.status === 'active' ? '🟢' : plugin.status === 'error' ? '🔴' : '🟡';
                const enabled = plugin.enabled ? '🟢' : '🔴';
                console.log(`${status} ${chalk_1.default.cyan(plugin.manifest.name)} (${plugin.id})`);
                console.log(`   Description: ${plugin.manifest.description}`);
                console.log(`   Version: ${plugin.manifest.version}`);
                console.log(`   Author: ${plugin.manifest.author}`);
                console.log(`   Status: ${plugin.status} | Enabled: ${enabled}`);
                console.log(`   Tools: ${plugin.manifest.tools.length}`);
                if (plugin.loadTime) {
                    console.log(`   Load Time: ${plugin.loadTime}ms`);
                }
                console.log('');
            });
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to get plugins:'), error);
        }
    }
    async showPlugin(id) {
        this.startSpinner('Getting plugin details...');
        try {
            const plugin = this.pluginManager.getPlugin(id);
            this.stopSpinner();
            if (!plugin) {
                console.log(chalk_1.default.red(`Plugin not found: ${id}`));
                return;
            }
            console.log(chalk_1.default.blue.bold(`\n🔌 Plugin: ${plugin.manifest.name}`));
            console.log(chalk_1.default.gray('─'.repeat(80)));
            console.log(chalk_1.default.cyan('ID:'), plugin.id);
            console.log(chalk_1.default.cyan('Description:'), plugin.manifest.description);
            console.log(chalk_1.default.cyan('Version:'), plugin.manifest.version);
            console.log(chalk_1.default.cyan('Author:'), plugin.manifest.author);
            console.log(chalk_1.default.cyan('License:'), plugin.manifest.license);
            console.log(chalk_1.default.cyan('Status:'), plugin.status);
            console.log(chalk_1.default.cyan('Enabled:'), plugin.enabled ? 'Yes' : 'No');
            console.log(chalk_1.default.cyan('Tools:'), plugin.manifest.tools.length);
            console.log(chalk_1.default.cyan('Usage Count:'), plugin.usageCount);
            if (plugin.manifest.tags && plugin.manifest.tags.length > 0) {
                console.log(chalk_1.default.cyan('Tags:'), plugin.manifest.tags.join(', '));
            }
            if (plugin.manifest.repository) {
                console.log(chalk_1.default.cyan('Repository:'), plugin.manifest.repository);
            }
            if (plugin.error) {
                console.log(chalk_1.default.red('Error:'), plugin.error);
            }
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to get plugin details:'), error);
        }
    }
    async loadPlugin(id) {
        this.startSpinner('Loading plugin...');
        try {
            const plugin = await this.pluginManager.loadPlugin(id);
            this.stopSpinner();
            if (plugin) {
                console.log(chalk_1.default.green.bold('\n✅ Plugin loaded successfully'));
                console.log(chalk_1.default.cyan('Name:'), plugin.manifest.name);
                console.log(chalk_1.default.cyan('Tools:'), plugin.manifest.tools.length);
                console.log(chalk_1.default.cyan('Load Time:'), `${plugin.loadTime}ms`);
            }
            else {
                console.log(chalk_1.default.red('Failed to load plugin'));
            }
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to load plugin:'), error);
        }
    }
    async unloadPlugin(id) {
        this.startSpinner('Unloading plugin...');
        try {
            const success = await this.pluginManager.unloadPlugin(id);
            this.stopSpinner();
            if (success) {
                console.log(chalk_1.default.green.bold('\n✅ Plugin unloaded successfully'));
            }
            else {
                console.log(chalk_1.default.red('Failed to unload plugin'));
            }
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to unload plugin:'), error);
        }
    }
    async togglePlugin(id) {
        try {
            const plugin = this.pluginManager.getPlugin(id);
            if (!plugin) {
                console.log(chalk_1.default.red(`Plugin not found: ${id}`));
                return;
            }
            const action = plugin.enabled ? 'disable' : 'enable';
            this.startSpinner(`${action}ing plugin...`);
            let success = false;
            if (action === 'enable') {
                success = await this.pluginManager.enablePlugin(id);
            }
            else {
                success = await this.pluginManager.disablePlugin(id);
            }
            this.stopSpinner();
            if (success) {
                console.log(chalk_1.default.green.bold(`\n✅ Plugin ${action}d successfully`));
            }
            else {
                console.log(chalk_1.default.red(`Failed to ${action} plugin`));
            }
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to toggle plugin:'), error);
        }
    }
    async showPluginTools(id) {
        this.startSpinner('Getting plugin tools...');
        try {
            const tools = this.pluginManager.getPluginTools(id);
            this.stopSpinner();
            if (tools.length === 0) {
                console.log(chalk_1.default.yellow('No tools available for this plugin'));
                return;
            }
            console.log(chalk_1.default.blue.bold(`\n🔧 Plugin Tools: ${id}`));
            console.log(chalk_1.default.gray('─'.repeat(80)));
            tools.forEach(tool => {
                console.log(chalk_1.default.cyan(`${tool.name} (${tool.id})`));
                console.log(`   Description: ${tool.description}`);
                console.log(`   Category: ${tool.category}`);
                if (tool.examples && tool.examples.length > 0) {
                    console.log(`   Examples: ${tool.examples.length}`);
                }
                console.log('');
            });
        }
        catch (error) {
            this.stopSpinner();
            console.error(chalk_1.default.red('Failed to get plugin tools:'), error);
        }
    }
    async startWebServer(port, host) {
        try {
            console.log(chalk_1.default.blue.bold(`\n🚀 Starting MCP God Mode Web Server...`));
            console.log(chalk_1.default.cyan('Port:'), port);
            console.log(chalk_1.default.cyan('Host:'), host);
            const server = new web_server_js_1.WebServer({
                port,
                host,
                enableCors: true,
                corsOrigin: ['http://localhost:3000', 'http://localhost:3001'],
                enableCompression: true,
                enableLogging: true,
                staticPath: './public',
                apiPrefix: '/api/v1'
            });
            await server.start();
            console.log(chalk_1.default.green.bold('\n✅ Web server started successfully'));
            console.log(chalk_1.default.cyan('Dashboard:'), `http://${host}:${port}`);
            console.log(chalk_1.default.cyan('API:'), `http://${host}:${port}/api/v1`);
            console.log(chalk_1.default.gray('\nPress Ctrl+C to stop the server'));
            // Keep the process alive
            process.on('SIGINT', async () => {
                console.log('\nShutting down web server...');
                await server.stop();
                process.exit(0);
            });
        }
        catch (error) {
            console.error(chalk_1.default.red('Failed to start web server:'), error);
        }
    }
    async stopWebServer() {
        console.log(chalk_1.default.yellow('Web server stop command not implemented in CLI mode'));
        console.log(chalk_1.default.yellow('Use Ctrl+C if the server is running, or stop the process manually'));
    }
    async showWebServerStatus() {
        console.log(chalk_1.default.yellow('Web server status command not implemented in CLI mode'));
        console.log(chalk_1.default.yellow('Check if the server is running by visiting the dashboard URL'));
    }
    async startInteractiveMode() {
        console.log(chalk_1.default.blue.bold('\n🎯 MCP God Mode Interactive Mode'));
        console.log(chalk_1.default.gray('Type "help" for available commands, "exit" to quit'));
        console.log(chalk_1.default.gray('─'.repeat(50)));
        const rl = require('readline').createInterface({
            input: process.stdin,
            output: process.stdout
        });
        const askQuestion = () => {
            rl.question(chalk_1.default.cyan('mcp-god-mode> '), async (input) => {
                const command = input.trim().toLowerCase();
                if (command === 'exit' || command === 'quit') {
                    console.log(chalk_1.default.blue('Goodbye! 👋'));
                    rl.close();
                    return;
                }
                if (command === 'help') {
                    console.log(chalk_1.default.green.bold('\n📚 Available Commands:'));
                    console.log(chalk_1.default.cyan('system info'), '- Show system information');
                    console.log(chalk_1.default.cyan('system health'), '- Check system health');
                    console.log(chalk_1.default.cyan('monitoring metrics'), '- Show current metrics');
                    console.log(chalk_1.default.cyan('monitoring alerts'), '- Show system alerts');
                    console.log(chalk_1.default.cyan('workflow list'), '- List all workflows');
                    console.log(chalk_1.default.cyan('plugin list'), '- List all plugins');
                    console.log(chalk_1.default.cyan('web start'), '- Start web server');
                    console.log(chalk_1.default.cyan('help'), '- Show this help');
                    console.log(chalk_1.default.cyan('exit'), '- Exit interactive mode');
                }
                else if (command === 'system info') {
                    await this.showSystemInfo();
                }
                else if (command === 'system health') {
                    await this.checkSystemHealth();
                }
                else if (command === 'monitoring metrics') {
                    await this.showMetrics(10);
                }
                else if (command === 'monitoring alerts') {
                    await this.showAlerts();
                }
                else if (command === 'workflow list') {
                    await this.listWorkflows();
                }
                else if (command === 'plugin list') {
                    await this.listPlugins();
                }
                else if (command === 'web start') {
                    await this.startWebServer(3000, 'localhost');
                }
                else if (command !== '') {
                    console.log(chalk_1.default.red(`Unknown command: ${command}`));
                    console.log(chalk_1.default.yellow('Type "help" for available commands'));
                }
                console.log(''); // Empty line for readability
                askQuestion();
            });
        };
        askQuestion();
    }
    // Utility methods
    startSpinner(text) {
        if (this.config.enableSpinners) {
            this.spinner = (0, ora_1.default)(text).start();
        }
    }
    stopSpinner() {
        if (this.spinner) {
            this.spinner.stop();
            this.spinner = null;
        }
    }
    // Run the CLI
    async run() {
        try {
            await this.program.parseAsync();
        }
        catch (error) {
            console.error(chalk_1.default.red('CLI error:'), error);
            process.exit(1);
        }
    }
}
exports.MCPGodModeCLI = MCPGodModeCLI;
// Start CLI if this file is run directly
if (process.argv[1] && process.argv[1].endsWith('cli.js')) {
    const cli = new MCPGodModeCLI();
    cli.run();
}
