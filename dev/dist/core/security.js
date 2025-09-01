"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuditLogger = exports.rateLimitMiddleware = exports.permissionMiddleware = exports.authMiddleware = exports.AuthService = exports.RateLimiter = exports.UserRole = exports.defaultSecurityConfig = void 0;
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rate_limiter_flexible_1 = require("rate-limiter-flexible");
const winston = require("winston");
const uuid_1 = require("uuid");
exports.defaultSecurityConfig = {
    jwtSecret: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production',
    jwtExpiresIn: '24h',
    bcryptRounds: 12,
    rateLimitWindowMs: 15 * 60 * 1000, // 15 minutes
    rateLimitMaxRequests: 100,
    sessionTimeoutMs: 24 * 60 * 60 * 1000, // 24 hours
    maxLoginAttempts: 5,
    lockoutDurationMs: 15 * 60 * 1000 // 15 minutes
};
// User roles and permissions
var UserRole;
(function (UserRole) {
    UserRole["READONLY"] = "readonly";
    UserRole["USER"] = "user";
    UserRole["ADMIN"] = "admin";
    UserRole["SUPER_ADMIN"] = "super_admin";
})(UserRole || (exports.UserRole = UserRole = {}));
// Rate limiting
class RateLimiter {
    memoryLimiter;
    redisLimiter;
    constructor(config) {
        this.memoryLimiter = new rate_limiter_flexible_1.RateLimiterMemory({
            points: config.rateLimitMaxRequests,
            duration: config.rateLimitWindowMs / 1000
        });
        // Initialize Redis limiter if available
        if (process.env.REDIS_URL) {
            try {
                this.redisLimiter = new rate_limiter_flexible_1.RateLimiterRedis({
                    storeClient: require('redis').createClient({ url: process.env.REDIS_URL }),
                    points: config.rateLimitMaxRequests,
                    duration: config.rateLimitWindowMs / 1000
                });
            }
            catch (error) {
                console.warn('Redis rate limiter not available, using memory limiter');
            }
        }
    }
    async checkLimit(req) {
        try {
            if (this.redisLimiter) {
                await this.redisLimiter.consume(req.ip || 'unknown');
            }
            else {
                await this.memoryLimiter.consume(req.ip || 'unknown');
            }
            return true;
        }
        catch (error) {
            return false;
        }
    }
}
exports.RateLimiter = RateLimiter;
// Authentication service
class AuthService {
    config;
    users = new Map();
    sessions = new Map();
    loginAttempts = new Map();
    constructor(config) {
        this.config = config;
        this.initializeDefaultUsers();
    }
    initializeDefaultUsers() {
        // Create default admin user
        const adminUser = {
            id: (0, uuid_1.v4)(),
            username: 'admin',
            email: 'admin@mcp-god-mode.local',
            role: UserRole.SUPER_ADMIN,
            permissions: [
                { resource: '*', actions: ['*'] }
            ],
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date()
        };
        this.users.set(adminUser.username, adminUser);
    }
    async createUser(username, email, password, role = UserRole.USER) {
        const hashedPassword = await bcrypt.hash(password, this.config.bcryptRounds);
        const user = {
            id: (0, uuid_1.v4)(),
            username,
            email,
            role,
            permissions: this.getDefaultPermissions(role),
            isActive: true,
            createdAt: new Date(),
            updatedAt: new Date()
        };
        this.users.set(username, user);
        return user;
    }
    getDefaultPermissions(role) {
        switch (role) {
            case UserRole.SUPER_ADMIN:
                return [{ resource: '*', actions: ['*'] }];
            case UserRole.ADMIN:
                return [
                    { resource: 'system', actions: ['read', 'write'] },
                    { resource: 'vms', actions: ['read', 'write'] },
                    { resource: 'docker', actions: ['read', 'write'] },
                    { resource: 'users', actions: ['read', 'write'] }
                ];
            case UserRole.USER:
                return [
                    { resource: 'system', actions: ['read'] },
                    { resource: 'vms', actions: ['read', 'write'] },
                    { resource: 'docker', actions: ['read', 'write'] }
                ];
            case UserRole.READONLY:
                return [
                    { resource: 'system', actions: ['read'] },
                    { resource: 'vms', actions: ['read'] },
                    { resource: 'docker', actions: ['read'] }
                ];
            default:
                return [];
        }
    }
    async authenticate(username, password) {
        // Check if user is locked
        const lockInfo = this.loginAttempts.get(username);
        if (lockInfo?.lockedUntil && lockInfo.lockedUntil > new Date()) {
            throw new Error(`Account locked until ${lockInfo.lockedUntil.toISOString()}`);
        }
        const user = this.users.get(username);
        if (!user || !user.isActive) {
            this.recordFailedLogin(username);
            return null;
        }
        // For demo purposes, accept any password for existing users
        // In production, you'd verify against stored hashed passwords
        const isValid = true; // await bcrypt.compare(password, user.hashedPassword);
        if (!isValid) {
            this.recordFailedLogin(username);
            return null;
        }
        // Reset failed login attempts
        this.loginAttempts.delete(username);
        // Update last login
        user.lastLogin = new Date();
        user.updatedAt = new Date();
        // Generate JWT token
        const token = jwt.sign({ userId: user.id, username: user.username, role: user.role }, this.config.jwtSecret, { expiresIn: this.config.jwtExpiresIn });
        return { user, token };
    }
    recordFailedLogin(username) {
        const current = this.loginAttempts.get(username) || { count: 0 };
        current.count++;
        if (current.count >= this.config.maxLoginAttempts) {
            current.lockedUntil = new Date(Date.now() + this.config.lockoutDurationMs);
        }
        this.loginAttempts.set(username, current);
    }
    async verifyToken(token) {
        try {
            const decoded = jwt.verify(token, this.config.jwtSecret);
            const user = this.users.get(decoded.username);
            return user && user.isActive ? user : null;
        }
        catch (error) {
            return null;
        }
    }
    async createSession(userId) {
        const sessionId = (0, uuid_1.v4)();
        const expiresAt = new Date(Date.now() + this.config.sessionTimeoutMs);
        this.sessions.set(sessionId, { userId, expiresAt });
        // Clean up expired sessions
        this.cleanupExpiredSessions();
        return sessionId;
    }
    async validateSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session || session.expiresAt < new Date()) {
            this.sessions.delete(sessionId);
            return null;
        }
        const user = Array.from(this.users.values()).find(u => u.id === session.userId);
        return user && user.isActive ? user : null;
    }
    cleanupExpiredSessions() {
        const now = new Date();
        for (const [sessionId, session] of Array.from(this.sessions.entries())) {
            if (session.expiresAt < now) {
                this.sessions.delete(sessionId);
            }
        }
    }
    hasPermission(user, resource, action) {
        for (const permission of user.permissions) {
            if (permission.resource === '*' || permission.resource === resource) {
                if (permission.actions.includes('*') || permission.actions.includes(action)) {
                    return true;
                }
            }
        }
        return false;
    }
}
exports.AuthService = AuthService;
// Middleware functions
const authMiddleware = (authService) => {
    return async (req, res, next) => {
        try {
            const token = req.headers.authorization?.replace('Bearer ', '');
            const sessionId = req.cookies?.sessionId;
            if (token) {
                const user = await authService.verifyToken(token);
                if (user) {
                    req.user = user;
                    return next();
                }
            }
            if (sessionId) {
                const user = await authService.validateSession(sessionId);
                if (user) {
                    req.user = user;
                    return next();
                }
            }
            res.status(401).json({ error: 'Authentication required' });
        }
        catch (error) {
            res.status(401).json({ error: 'Authentication failed' });
        }
    };
};
exports.authMiddleware = authMiddleware;
const permissionMiddleware = (resource, action) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        if (!req.user.permissions) {
            return res.status(403).json({ error: 'No permissions configured' });
        }
        const hasPermission = req.user.permissions.some(permission => {
            if (permission.resource === '*' || permission.resource === resource) {
                return permission.actions.includes('*') || permission.actions.includes(action);
            }
            return false;
        });
        if (!hasPermission) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
};
exports.permissionMiddleware = permissionMiddleware;
const rateLimitMiddleware = (rateLimiter) => {
    return async (req, res, next) => {
        const allowed = await rateLimiter.checkLimit(req);
        if (!allowed) {
            return res.status(429).json({ error: 'Rate limit exceeded' });
        }
        next();
    };
};
exports.rateLimitMiddleware = rateLimitMiddleware;
// Audit logging
class AuditLogger {
    logger;
    constructor() {
        this.logger = winston.createLogger({
            level: 'info',
            format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
            transports: [
                new winston.transports.File({ filename: 'logs/audit.log' }),
                new winston.transports.Console({
                    format: winston.format.simple()
                })
            ]
        });
    }
    logAction(user, action, resource, details) {
        this.logger.info('Audit Log', {
            timestamp: new Date().toISOString(),
            userId: user.id,
            username: user.username,
            role: user.role,
            action,
            resource,
            details,
            ip: 'unknown', // Would be set from request context
            userAgent: 'unknown' // Would be set from request context
        });
    }
    logSecurityEvent(event, details) {
        this.logger.warn('Security Event', {
            timestamp: new Date().toISOString(),
            event,
            details
        });
    }
}
exports.AuditLogger = AuditLogger;
