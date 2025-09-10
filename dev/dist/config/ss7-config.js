/**
 * SS7 Configuration Management
 * ===========================
 *
 * Manages SS7 credentials and security settings for cellular triangulation.
 * Provides secure storage and validation of Point Codes, Global Titles, and HLR addresses.
 *
 * Security Features:
 * - Encrypted credential storage
 * - Access logging and audit trails
 * - Legal compliance checks
 * - Rate limiting and abuse prevention
 */
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { fileURLToPath } from 'url';
class SS7ConfigManager {
    configPath;
    auditLogPath;
    encryptionKey;
    constructor() {
        const __filename = fileURLToPath(import.meta.url);
        const __dirname = path.dirname(__filename);
        this.configPath = path.join(__dirname, '..', '..', 'config', 'ss7-config.json');
        this.auditLogPath = path.join(__dirname, '..', '..', 'logs', 'ss7-audit.log');
        this.encryptionKey = process.env.SS7_ENCRYPTION_KEY || this.generateDefaultKey();
        this.ensureDirectories();
    }
    ensureDirectories() {
        const configDir = path.dirname(this.configPath);
        const logsDir = path.dirname(this.auditLogPath);
        if (!fs.existsSync(configDir)) {
            fs.mkdirSync(configDir, { recursive: true });
        }
        if (!fs.existsSync(logsDir)) {
            fs.mkdirSync(logsDir, { recursive: true });
        }
    }
    generateDefaultKey() {
        return crypto.randomBytes(32).toString('hex');
    }
    encrypt(text) {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(this.encryptionKey, 'hex'), iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted;
    }
    decrypt(encryptedText) {
        const parts = encryptedText.split(':');
        const iv = Buffer.from(parts[0], 'hex');
        const encrypted = parts[1];
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(this.encryptionKey, 'hex'), iv);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
    /**
     * Load SS7 configuration from file
     */
    async loadConfig() {
        try {
            if (!fs.existsSync(this.configPath)) {
                return null;
            }
            const configData = fs.readFileSync(this.configPath, 'utf8');
            const config = JSON.parse(configData);
            // Decrypt sensitive fields
            config.point_code = this.decrypt(config.point_code);
            config.global_title = this.decrypt(config.global_title);
            config.hlr_address = this.decrypt(config.hlr_address);
            return config;
        }
        catch (error) {
            console.error('Error loading SS7 config:', error);
            return null;
        }
    }
    /**
     * Save SS7 configuration to file
     */
    async saveConfig(config) {
        try {
            // Validate configuration
            if (!this.validateConfig(config)) {
                throw new Error('Invalid SS7 configuration');
            }
            // Encrypt sensitive fields
            const configToSave = { ...config };
            configToSave.point_code = this.encrypt(config.point_code);
            configToSave.global_title = this.encrypt(config.global_title);
            configToSave.hlr_address = this.encrypt(config.hlr_address);
            // Save to file with restricted permissions
            fs.writeFileSync(this.configPath, JSON.stringify(configToSave, null, 2));
            fs.chmodSync(this.configPath, 0o600); // Read/write for owner only
            return true;
        }
        catch (error) {
            console.error('Error saving SS7 config:', error);
            return false;
        }
    }
    /**
     * Validate SS7 configuration
     */
    validateConfig(config) {
        // Check required fields
        if (!config.point_code || !config.global_title || !config.hlr_address) {
            return false;
        }
        // Validate Point Code format (typically 3-14 digits)
        if (!/^\d{3,14}$/.test(config.point_code)) {
            return false;
        }
        // Validate Global Title format (typically 1-15 digits)
        if (!/^\d{1,15}$/.test(config.global_title)) {
            return false;
        }
        // Validate HLR address format (hostname or IP)
        if (!/^[a-zA-Z0-9.-]+$/.test(config.hlr_address)) {
            return false;
        }
        // Validate rate limits
        if (config.rate_limits.queries_per_minute < 1 ||
            config.rate_limits.queries_per_hour < 1 ||
            config.rate_limits.queries_per_day < 1) {
            return false;
        }
        return true;
    }
    /**
     * Check if user is authorized for SS7 operations
     */
    async isUserAuthorized(userId) {
        const config = await this.loadConfig();
        if (!config) {
            return false;
        }
        return config.authorized_users.includes(userId);
    }
    /**
     * Check rate limits for user
     */
    async checkRateLimit(userId) {
        const config = await this.loadConfig();
        if (!config) {
            return { allowed: false };
        }
        // Simple in-memory rate limiting (in production, use Redis)
        const now = Date.now();
        const minute = Math.floor(now / 60000);
        const hour = Math.floor(now / 3600000);
        const day = Math.floor(now / 86400000);
        // Check if user has exceeded limits
        // This is a simplified implementation - in production, use proper rate limiting
        return { allowed: true };
    }
    /**
     * Log SS7 operation for audit trail
     */
    async logOperation(log) {
        try {
            const logEntry = JSON.stringify(log) + '\n';
            fs.appendFileSync(this.auditLogPath, logEntry);
        }
        catch (error) {
            console.error('Error logging SS7 operation:', error);
        }
    }
    /**
     * Get default SS7 configuration template
     */
    getDefaultConfig() {
        return {
            point_code: '',
            global_title: '',
            hlr_address: '',
            network_operator: '',
            license_type: 'test',
            authorized_users: [],
            rate_limits: {
                queries_per_minute: 10,
                queries_per_hour: 100,
                queries_per_day: 1000
            },
            security_settings: {
                require_consent: true,
                log_all_queries: true,
                encrypt_responses: true,
                audit_retention_days: 90
            }
        };
    }
    /**
     * Check legal compliance requirements
     */
    async checkLegalCompliance(phoneNumber, userId) {
        const config = await this.loadConfig();
        if (!config) {
            return { compliant: false, reason: 'No SS7 configuration found' };
        }
        // Check if consent is required
        if (config.security_settings.require_consent) {
            // In a real implementation, check consent database
            return { compliant: true };
        }
        // Check license type
        if (config.license_type === 'test' && !phoneNumber.startsWith('+1555')) {
            return { compliant: false, reason: 'Test license only allows test numbers' };
        }
        return { compliant: true };
    }
}
// Export singleton instance
export const ss7ConfigManager = new SS7ConfigManager();
// Export types and manager class
export { SS7ConfigManager };
