"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.SystemMonitor = exports.defaultMonitoringConfig = void 0;
const os = __importStar(require("node:os"));
const events_1 = require("events");
const winston = require("winston");
const node_child_process_1 = require("node:child_process");
const node_util_1 = require("node:util");
// Simple scheduler for monitoring
class MonitoringScheduler {
    jobs = new Map();
    scheduleJob(id, intervalMs, callback) {
        const timer = setInterval(callback, intervalMs);
        this.jobs.set(id, { interval: intervalMs, callback, timer });
    }
    stopJob(id) {
        const job = this.jobs.get(id);
        if (job && job.timer) {
            clearInterval(job.timer);
            this.jobs.delete(id);
        }
    }
    stopAll() {
        for (const [id, job] of Array.from(this.jobs.entries())) {
            if (job.timer) {
                clearInterval(job.timer);
            }
        }
        this.jobs.clear();
    }
}
const execAsync = (0, node_util_1.promisify)(node_child_process_1.exec);
exports.defaultMonitoringConfig = {
    collectionInterval: 5000, // 5 seconds
    retentionDays: 30,
    alertCheckInterval: 10000, // 10 seconds
    baselineUpdateInterval: 300000, // 5 minutes
    thresholds: {
        cpu: { warning: 70, critical: 90 },
        memory: { warning: 80, critical: 95 },
        disk: { warning: 85, critical: 95 },
        network: { warning: 80, critical: 95 }
    }
};
// System monitoring service
class SystemMonitor extends events_1.EventEmitter {
    config;
    logger;
    metrics = [];
    alerts = [];
    alertRules = [];
    baselines = new Map();
    scheduler;
    networkStats = {
        bytesIn: 0,
        bytesOut: 0,
        packetsIn: 0,
        packetsOut: 0
    };
    constructor(config = exports.defaultMonitoringConfig) {
        super();
        this.config = config;
        this.scheduler = new MonitoringScheduler();
        this.logger = winston.createLogger({
            level: 'info',
            format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
            transports: [
                new winston.transports.File({ filename: 'logs/monitoring.log' }),
                new winston.transports.Console({
                    format: winston.format.simple()
                })
            ]
        });
        this.initializeDefaultAlertRules();
        this.startMonitoring();
    }
    initializeDefaultAlertRules() {
        this.alertRules = [
            {
                id: 'cpu-high',
                name: 'High CPU Usage',
                resource: 'cpu',
                metric: 'usage',
                operator: 'gt',
                threshold: this.config.thresholds.cpu.warning,
                duration: 60,
                level: 'warning',
                enabled: true,
                actions: ['email', 'webhook']
            },
            {
                id: 'cpu-critical',
                name: 'Critical CPU Usage',
                resource: 'cpu',
                metric: 'usage',
                operator: 'gt',
                threshold: this.config.thresholds.cpu.critical,
                duration: 30,
                level: 'critical',
                enabled: true,
                actions: ['email', 'webhook', 'sms']
            },
            {
                id: 'memory-high',
                name: 'High Memory Usage',
                resource: 'memory',
                metric: 'usage',
                operator: 'gt',
                threshold: this.config.thresholds.memory.warning,
                duration: 60,
                level: 'warning',
                enabled: true,
                actions: ['email', 'webhook']
            },
            {
                id: 'disk-high',
                name: 'High Disk Usage',
                resource: 'disk',
                metric: 'usage',
                operator: 'gt',
                threshold: this.config.thresholds.disk.warning,
                duration: 300,
                level: 'warning',
                enabled: true,
                actions: ['email', 'webhook']
            }
        ];
    }
    startMonitoring() {
        // Start metrics collection
        this.scheduler.scheduleJob('metrics-collection', this.config.collectionInterval, () => this.collectMetrics());
        // Start alert checking
        this.scheduler.scheduleJob('alert-checking', this.config.alertCheckInterval, () => this.checkAlerts());
        // Start baseline updates
        this.scheduler.scheduleJob('baseline-updates', this.config.baselineUpdateInterval, () => this.updateBaselines());
        this.logger.info('System monitoring started');
    }
    async collectMetrics() {
        try {
            const metrics = await this.gatherSystemMetrics();
            this.metrics.push(metrics);
            // Keep only recent metrics
            const cutoff = new Date(Date.now() - (this.config.retentionDays * 24 * 60 * 60 * 1000));
            this.metrics = this.metrics.filter(m => m.timestamp > cutoff);
            this.emit('metrics', metrics);
            this.logger.debug('Metrics collected', { timestamp: metrics.timestamp });
        }
        catch (error) {
            this.logger.error('Failed to collect metrics', { error: error instanceof Error ? error.message : String(error) });
        }
    }
    async gatherSystemMetrics() {
        const platform = os.platform();
        // CPU metrics
        const cpus = os.cpus();
        const cpuUsage = await this.getCPUUsage();
        const loadAverage = os.loadavg();
        // Memory metrics
        const totalMem = os.totalmem();
        const freeMem = os.freemem();
        const usedMem = totalMem - freeMem;
        // Disk metrics
        const diskUsage = await this.getDiskUsage(platform);
        // Process metrics
        const processCounts = await this.getProcessCounts(platform);
        // Network metrics
        const networkStats = await this.getNetworkStats(platform);
        return {
            timestamp: new Date(),
            cpu: {
                usage: cpuUsage,
                loadAverage,
                cores: cpus.length
            },
            memory: {
                total: totalMem,
                used: usedMem,
                free: freeMem,
                available: freeMem,
                usage: (usedMem / totalMem) * 100
            },
            disk: diskUsage,
            network: networkStats,
            processes: processCounts,
            uptime: os.uptime(),
            platform,
            arch: os.arch()
        };
    }
    async getCPUUsage() {
        try {
            if (os.platform() === 'win32') {
                const { stdout } = await execAsync('wmic cpu get loadpercentage /value');
                const match = stdout.match(/LoadPercentage=(\d+)/);
                return match ? parseInt(match[1]) : 0;
            }
            else {
                const { stdout } = await execAsync("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | awk -F'%' '{print $1}'");
                return parseFloat(stdout.trim()) || 0;
            }
        }
        catch (error) {
            return 0;
        }
    }
    async getDiskUsage(platform) {
        try {
            if (platform === 'win32') {
                const { stdout } = await execAsync('wmic logicaldisk get size,freespace /value');
                const lines = stdout.split('\n');
                let total = 0, free = 0;
                for (const line of lines) {
                    if (line.includes('Size=')) {
                        total += parseInt(line.split('=')[1]) || 0;
                    }
                    else if (line.includes('FreeSpace=')) {
                        free += parseInt(line.split('=')[1]) || 0;
                    }
                }
                const used = total - free;
                return { total, used, free, usage: (used / total) * 100 };
            }
            else {
                const { stdout } = await execAsync("df -k / | tail -1 | awk '{print $2, $3, $4}'");
                const [total, used, free] = stdout.trim().split(' ').map(Number);
                return { total: total * 1024, used: used * 1024, free: free * 1024, usage: (used / total) * 100 };
            }
        }
        catch (error) {
            return { total: 0, used: 0, free: 0, usage: 0 };
        }
    }
    async getProcessCounts(platform) {
        try {
            if (platform === 'win32') {
                const { stdout } = await execAsync('tasklist /fo csv | find /c ""');
                const total = parseInt(stdout.trim()) - 1; // Subtract header
                return { total, running: total, sleeping: 0, stopped: 0, zombie: 0 };
            }
            else {
                const { stdout } = await execAsync("ps aux | wc -l");
                const total = parseInt(stdout.trim()) - 1; // Subtract header
                return { total, running: total, sleeping: 0, stopped: 0, zombie: 0 };
            }
        }
        catch (error) {
            return { total: 0, running: 0, sleeping: 0, stopped: 0, zombie: 0 };
        }
    }
    async getNetworkStats(platform) {
        // This is a simplified implementation
        // In production, you'd use more sophisticated network monitoring
        return this.networkStats;
    }
    checkAlerts() {
        if (this.metrics.length === 0)
            return;
        const latestMetrics = this.metrics[this.metrics.length - 1];
        for (const rule of this.alertRules) {
            if (!rule.enabled)
                continue;
            const value = this.getMetricValue(latestMetrics, rule.resource, rule.metric);
            if (value === null)
                continue;
            const shouldAlert = this.evaluateThreshold(value, rule.operator, rule.threshold);
            if (shouldAlert) {
                const alert = {
                    id: `${rule.id}-${Date.now()}`,
                    level: rule.level,
                    message: rule.name,
                    resource: rule.resource,
                    value,
                    threshold: rule.threshold,
                    timestamp: new Date(),
                    acknowledged: false
                };
                this.alerts.push(alert);
                this.emit('alert', alert);
                this.logger.warn('Alert triggered', alert);
                // Execute alert actions
                this.executeAlertActions(alert, rule.actions);
            }
        }
    }
    getMetricValue(metrics, resource, metric) {
        switch (resource) {
            case 'cpu':
                return metrics.cpu[metric];
            case 'memory':
                return metrics.memory[metric];
            case 'disk':
                return metrics.disk[metric];
            case 'network':
                return metrics.network[metric];
            default:
                return null;
        }
    }
    evaluateThreshold(value, operator, threshold) {
        switch (operator) {
            case 'gt': return value > threshold;
            case 'lt': return value < threshold;
            case 'eq': return value === threshold;
            case 'gte': return value >= threshold;
            case 'lte': return value <= threshold;
            default: return false;
        }
    }
    async executeAlertActions(alert, actions) {
        for (const action of actions) {
            try {
                switch (action) {
                    case 'email':
                        await this.sendEmailAlert(alert);
                        break;
                    case 'webhook':
                        await this.sendWebhookAlert(alert);
                        break;
                    case 'sms':
                        await this.sendSMSAlert(alert);
                        break;
                }
            }
            catch (error) {
                this.logger.error(`Failed to execute alert action: ${action}`, { error: error instanceof Error ? error.message : String(error) });
            }
        }
    }
    async sendEmailAlert(alert) {
        // Implementation would integrate with your email service
        this.logger.info('Email alert sent', { alertId: alert.id });
    }
    async sendWebhookAlert(alert) {
        // Implementation would send HTTP POST to configured webhook URLs
        this.logger.info('Webhook alert sent', { alertId: alert.id });
    }
    async sendSMSAlert(alert) {
        // Implementation would integrate with SMS service
        this.logger.info('SMS alert sent', { alertId: alert.id });
    }
    updateBaselines() {
        if (this.metrics.length < 10)
            return; // Need minimum samples
        const resources = ['cpu', 'memory', 'disk', 'network'];
        const metrics = ['usage', 'loadAverage', 'usage', 'bytesIn'];
        for (let i = 0; i < resources.length; i++) {
            const resource = resources[i];
            const metric = metrics[i];
            const values = this.metrics
                .slice(-100) // Last 100 samples
                .map(m => this.getMetricValue(m, resource, metric))
                .filter(v => v !== null);
            if (values.length === 0)
                continue;
            const avg = values.reduce((a, b) => a + b, 0) / values.length;
            const min = Math.min(...values);
            const max = Math.max(...values);
            const stdDev = Math.sqrt(values.reduce((sq, n) => sq + Math.pow(n - avg, 2), 0) / values.length);
            const baseline = {
                resource,
                metric,
                avg,
                min,
                max,
                stdDev,
                samples: values.length,
                lastUpdated: new Date()
            };
            this.baselines.set(`${resource}.${metric}`, baseline);
        }
    }
    // Public methods
    getLatestMetrics() {
        return this.metrics.length > 0 ? this.metrics[this.metrics.length - 1] : null;
    }
    getMetricsHistory(limit = 100) {
        return this.metrics.slice(-limit);
    }
    getAlerts(acknowledged) {
        if (acknowledged === undefined)
            return this.alerts;
        return this.alerts.filter(a => a.acknowledged === acknowledged);
    }
    acknowledgeAlert(alertId, acknowledgedBy) {
        const alert = this.alerts.find(a => a.id === alertId);
        if (alert) {
            alert.acknowledged = true;
            alert.acknowledgedBy = acknowledgedBy;
            alert.acknowledgedAt = new Date();
            return true;
        }
        return false;
    }
    getBaselines() {
        return Array.from(this.baselines.values());
    }
    addAlertRule(rule) {
        this.alertRules.push(rule);
    }
    updateAlertRule(ruleId, updates) {
        const rule = this.alertRules.find(r => r.id === ruleId);
        if (rule) {
            Object.assign(rule, updates);
            return true;
        }
        return false;
    }
    deleteAlertRule(ruleId) {
        const index = this.alertRules.findIndex(r => r.id === ruleId);
        if (index !== -1) {
            this.alertRules.splice(index, 1);
            return true;
        }
        return false;
    }
    stop() {
        this.scheduler.stopAll();
        this.logger.info('System monitoring stopped');
    }
}
exports.SystemMonitor = SystemMonitor;
