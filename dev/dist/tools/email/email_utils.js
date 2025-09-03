"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getEmailTransport = getEmailTransport;
exports.extractLinksFromText = extractLinksFromText;
exports.extractEmailsFromText = extractEmailsFromText;
const nodemailer_1 = __importDefault(require("nodemailer"));
// Email configuration cache
const emailTransports = new Map();
async function getEmailTransport(config) {
    const cacheKey = `${config.service}-${config.email}-${config.host || 'default'}`;
    if (emailTransports.has(cacheKey)) {
        return emailTransports.get(cacheKey);
    }
    let transport;
    if (config.service === 'gmail') {
        transport = nodemailer_1.default.createTransport({
            service: 'gmail',
            auth: {
                user: config.email,
                pass: config.password
            }
        });
    }
    else if (config.service === 'outlook') {
        transport = nodemailer_1.default.createTransport({
            host: 'smtp-mail.outlook.com',
            port: 587,
            secure: false,
            auth: {
                user: config.email,
                pass: config.password
            }
        });
    }
    else if (config.service === 'yahoo') {
        transport = nodemailer_1.default.createTransport({
            host: 'smtp.mail.yahoo.com',
            port: 587,
            secure: false,
            auth: {
                user: config.email,
                pass: config.password
            }
        });
    }
    else {
        transport = nodemailer_1.default.createTransport({
            host: config.host,
            port: config.port || 587,
            secure: config.secure || false,
            auth: {
                user: config.email,
                pass: config.password
            }
        });
    }
    // Test the connection
    try {
        await transport.verify();
        emailTransports.set(cacheKey, transport);
        return transport;
    }
    catch (error) {
        throw new Error(`Failed to create email transport: ${error}`);
    }
}
function extractLinksFromText(text) {
    const urlRegex = /https?:\/\/[^\s]+/g;
    return text.match(urlRegex) || [];
}
function extractEmailsFromText(text) {
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    return text.match(emailRegex) || [];
}
