/**
 * SS7 Security Safeguards
 * =======================
 *
 * Implements security measures and legal compliance for SS7 operations.
 * Provides consent management, audit logging, and abuse prevention.
 */
import { ss7ConfigManager } from '../../config/ss7-config.js';
class SS7SecurityManager {
    consentDatabase = new Map();
    abuseDetection = new Map();
    /**
     * Perform comprehensive security check before SS7 operation
     */
    async performSecurityCheck(phoneNumber, userId, operation, ipAddress, userAgent) {
        const checks = [];
        // Check 1: User authorization
        const authCheck = await this.checkUserAuthorization(userId);
        checks.push(authCheck);
        // Check 2: Rate limiting
        const rateLimitCheck = await this.checkRateLimits(userId, ipAddress);
        checks.push(rateLimitCheck);
        // Check 3: Legal compliance
        const complianceCheck = await this.checkLegalCompliance(phoneNumber, userId);
        checks.push(complianceCheck);
        // Check 4: Consent verification
        const consentCheck = await this.checkConsent(phoneNumber, userId);
        checks.push(consentCheck);
        // Check 5: Abuse detection
        const abuseCheck = await this.checkAbusePatterns(phoneNumber, userId, ipAddress);
        checks.push(abuseCheck);
        // Check 6: Phone number validation
        const phoneCheck = this.validatePhoneNumber(phoneNumber);
        checks.push(phoneCheck);
        // Aggregate results
        const failedChecks = checks.filter(check => !check.passed);
        const highRiskChecks = checks.filter(check => check.risk_level === 'high');
        if (failedChecks.length > 0) {
            return {
                passed: false,
                reason: failedChecks.map(check => check.reason).join('; '),
                risk_level: highRiskChecks.length > 0 ? 'high' : 'medium',
                recommendations: this.generateRecommendations(failedChecks)
            };
        }
        return {
            passed: true,
            risk_level: 'low'
        };
    }
    /**
     * Check if user is authorized for SS7 operations
     */
    async checkUserAuthorization(userId) {
        const authorized = await ss7ConfigManager.isUserAuthorized(userId);
        if (!authorized) {
            return {
                passed: false,
                reason: 'User not authorized for SS7 operations',
                risk_level: 'high',
                recommendations: ['Contact administrator for SS7 access', 'Verify user credentials']
            };
        }
        return { passed: true, risk_level: 'low' };
    }
    /**
     * Check rate limits for user and IP
     */
    async checkRateLimits(userId, ipAddress) {
        const userRateLimit = await ss7ConfigManager.checkRateLimit(userId);
        if (!userRateLimit.allowed) {
            return {
                passed: false,
                reason: 'Rate limit exceeded for user',
                risk_level: 'medium',
                recommendations: ['Wait before retrying', 'Contact administrator if persistent']
            };
        }
        // Check IP-based rate limiting
        if (ipAddress) {
            const ipKey = `ip:${ipAddress}`;
            const ipData = this.abuseDetection.get(ipKey);
            if (ipData && ipData.count > 100 && (Date.now() - ipData.lastSeen) < 3600000) {
                return {
                    passed: false,
                    reason: 'Rate limit exceeded for IP address',
                    risk_level: 'high',
                    recommendations: ['IP address temporarily blocked', 'Contact administrator']
                };
            }
        }
        return { passed: true, risk_level: 'low' };
    }
    /**
     * Check legal compliance requirements
     */
    async checkLegalCompliance(phoneNumber, userId) {
        const compliance = await ss7ConfigManager.checkLegalCompliance(phoneNumber, userId);
        if (!compliance.compliant) {
            return {
                passed: false,
                reason: compliance.reason || 'Legal compliance check failed',
                risk_level: 'high',
                recommendations: ['Verify legal authorization', 'Check consent requirements']
            };
        }
        return { passed: true, risk_level: 'low' };
    }
    /**
     * Check if consent has been obtained
     */
    async checkConsent(phoneNumber, userId) {
        const consentKey = `${phoneNumber}:${userId}`;
        const consent = this.consentDatabase.get(consentKey);
        if (!consent) {
            return {
                passed: false,
                reason: 'No consent record found for phone number',
                risk_level: 'high',
                recommendations: ['Obtain explicit consent before querying', 'Document consent method']
            };
        }
        if (!consent.consent_given) {
            return {
                passed: false,
                reason: 'Consent not given for phone number',
                risk_level: 'high',
                recommendations: ['Obtain explicit consent', 'Document consent process']
            };
        }
        // Check if consent has expired
        if (consent.consent_expires && new Date(consent.consent_expires) < new Date()) {
            return {
                passed: false,
                reason: 'Consent has expired',
                risk_level: 'medium',
                recommendations: ['Obtain renewed consent', 'Update consent record']
            };
        }
        return { passed: true, risk_level: 'low' };
    }
    /**
     * Check for abuse patterns
     */
    async checkAbusePatterns(phoneNumber, userId, ipAddress) {
        const now = Date.now();
        const userKey = `user:${userId}`;
        const phoneKey = `phone:${phoneNumber}`;
        // Check user abuse patterns
        const userData = this.abuseDetection.get(userKey);
        if (userData && userData.count > 50 && (now - userData.lastSeen) < 3600000) {
            return {
                passed: false,
                reason: 'Suspicious activity detected for user',
                risk_level: 'high',
                recommendations: ['Account temporarily suspended', 'Contact administrator']
            };
        }
        // Check phone number abuse patterns
        const phoneData = this.abuseDetection.get(phoneKey);
        if (phoneData && phoneData.count > 20 && (now - phoneData.lastSeen) < 3600000) {
            return {
                passed: false,
                reason: 'Suspicious activity detected for phone number',
                risk_level: 'high',
                recommendations: ['Phone number temporarily blocked', 'Investigate potential abuse']
            };
        }
        return { passed: true, risk_level: 'low' };
    }
    /**
     * Validate phone number format and characteristics
     */
    validatePhoneNumber(phoneNumber) {
        // Basic format validation
        if (!/^\+[1-9]\d{1,14}$/.test(phoneNumber)) {
            return {
                passed: false,
                reason: 'Invalid phone number format',
                risk_level: 'medium',
                recommendations: ['Use international format (+country code)', 'Verify number accuracy']
            };
        }
        // Check for test numbers (allow in test environments)
        if (phoneNumber.startsWith('+1555') || phoneNumber.startsWith('+1556')) {
            return { passed: true, risk_level: 'low' };
        }
        // Check for suspicious patterns
        if (phoneNumber.match(/(\d)\1{6,}/)) {
            return {
                passed: false,
                reason: 'Suspicious phone number pattern detected',
                risk_level: 'medium',
                recommendations: ['Verify phone number accuracy', 'Check for typo']
            };
        }
        return { passed: true, risk_level: 'low' };
    }
    /**
     * Generate security recommendations
     */
    generateRecommendations(failedChecks) {
        const recommendations = [];
        failedChecks.forEach(check => {
            if (check.recommendations) {
                recommendations.push(...check.recommendations);
            }
        });
        return [...new Set(recommendations)]; // Remove duplicates
    }
    /**
     * Record consent for a phone number
     */
    async recordConsent(consent) {
        try {
            const consentKey = `${consent.phone_number}:${consent.user_id}`;
            this.consentDatabase.set(consentKey, consent);
            // Log consent recording
            await this.logSecurityEvent('consent_recorded', {
                phone_number: consent.phone_number,
                user_id: consent.user_id,
                consent_method: consent.consent_method
            });
            return true;
        }
        catch (error) {
            console.error('Error recording consent:', error);
            return false;
        }
    }
    /**
     * Log security event
     */
    async logSecurityEvent(event, details, userId, ipAddress) {
        const log = {
            timestamp: new Date().toISOString(),
            user_id: userId || 'system',
            action: event,
            result: 'success',
            ip_address: ipAddress,
            user_agent: details.user_agent
        };
        await ss7ConfigManager.logOperation(log);
    }
    /**
     * Update abuse detection counters
     */
    updateAbuseCounters(phoneNumber, userId, ipAddress) {
        const now = Date.now();
        // Update user counter
        const userKey = `user:${userId}`;
        const userData = this.abuseDetection.get(userKey) || { count: 0, lastSeen: 0 };
        userData.count++;
        userData.lastSeen = now;
        this.abuseDetection.set(userKey, userData);
        // Update phone number counter
        const phoneKey = `phone:${phoneNumber}`;
        const phoneData = this.abuseDetection.get(phoneKey) || { count: 0, lastSeen: 0 };
        phoneData.count++;
        phoneData.lastSeen = now;
        this.abuseDetection.set(phoneKey, phoneData);
        // Update IP counter if provided
        if (ipAddress) {
            const ipKey = `ip:${ipAddress}`;
            const ipData = this.abuseDetection.get(ipKey) || { count: 0, lastSeen: 0 };
            ipData.count++;
            ipData.lastSeen = now;
            this.abuseDetection.set(ipKey, ipData);
        }
    }
    /**
     * Get consent status for a phone number
     */
    getConsentStatus(phoneNumber, userId) {
        const consentKey = `${phoneNumber}:${userId}`;
        return this.consentDatabase.get(consentKey) || null;
    }
    /**
     * Clean up expired consent records
     */
    cleanupExpiredConsent() {
        const now = new Date();
        for (const [key, consent] of this.consentDatabase.entries()) {
            if (consent.consent_expires && new Date(consent.consent_expires) < now) {
                this.consentDatabase.delete(key);
            }
        }
    }
}
// Export singleton instance
export const ss7SecurityManager = new SS7SecurityManager();
// Export types and manager class
export { SS7SecurityManager };
