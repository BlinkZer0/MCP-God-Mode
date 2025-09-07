/**
 * Flipper Zero Integration Types
 * Shared types and interfaces for cross-platform Flipper Zero support
 */
// Error types
export class FlipperError extends Error {
    code;
    sessionId;
    constructor(message, code, sessionId) {
        super(message);
        this.code = code;
        this.sessionId = sessionId;
        this.name = 'FlipperError';
    }
}
export class FlipperTransportError extends FlipperError {
    constructor(message, sessionId) {
        super(message, 'TRANSPORT_ERROR', sessionId);
        this.name = 'FlipperTransportError';
    }
}
export class FlipperRPCError extends FlipperError {
    constructor(message, sessionId) {
        super(message, 'RPC_ERROR', sessionId);
        this.name = 'FlipperRPCError';
    }
}
export class FlipperSecurityError extends FlipperError {
    constructor(message, sessionId) {
        super(message, 'SECURITY_ERROR', sessionId);
        this.name = 'FlipperSecurityError';
    }
}
