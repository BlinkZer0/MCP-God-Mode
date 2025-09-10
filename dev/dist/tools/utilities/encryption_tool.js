import { z } from "zod";
import * as crypto from "node:crypto";
// Simple in-memory key store for basic key persistence
const keyStore = new Map();
// Helper function to create properly typed content
function createContent(text) {
    return [{ type: "text", text }];
}
// Helper function to generate proper AES key and IV
function generateAESKeyAndIV(password, salt) {
    const actualSalt = salt || crypto.randomBytes(16); // Generate random salt if not provided
    const key = crypto.scryptSync(password, actualSalt, 32); // 256-bit key
    const iv = crypto.randomBytes(16); // 128-bit IV
    return { key, iv, salt: actualSalt };
}
// Helper function to generate RSA key pair
function generateRSAKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
}
// Helper function to get or generate persistent RSA key pair
function getOrGenerateRSAKeyPair(keyId = "default") {
    const existing = keyStore.get(keyId);
    const now = Date.now();
    // Return existing key if it's less than 24 hours old
    if (existing && (now - existing.timestamp) < 24 * 60 * 60 * 1000) {
        return { publicKey: existing.publicKey, privateKey: existing.privateKey };
    }
    // Generate new key pair
    const { publicKey, privateKey } = generateRSAKeyPair();
    keyStore.set(keyId, { publicKey, privateKey, timestamp: now });
    return { publicKey, privateKey };
}
export function registerEncryptionTool(server) {
    server.registerTool("encryption_tool", {
        description: "Advanced encryption and cryptographic operations with proper AES, RSA, and hashing support",
        inputSchema: {
            action: z.enum(["encrypt", "decrypt", "hash", "sign", "verify", "generate_key"]).describe("Cryptographic action to perform"),
            algorithm: z.enum(["aes", "rsa", "sha256", "sha512", "md5"]).describe("Cryptographic algorithm to use"),
            input_data: z.string().describe("Data to process"),
            key: z.string().optional().describe("Encryption/decryption key or password"),
            mode: z.enum(["cbc", "gcm", "ecb"]).optional().default("cbc").describe("Encryption mode for AES")
        },
        outputSchema: z.object({
            success: z.boolean(),
            message: z.string(),
            result: z.string().optional(),
            full_result: z.string().optional(),
            result_length: z.number().optional(),
            error_type: z.string().optional(),
            timestamp: z.string().optional(),
            key_info: z.object({
                algorithm: z.string(),
                key_size: z.number(),
                mode: z.string().optional(),
                iv: z.string().optional(),
                salt: z.string().optional()
            }).optional()
        })
    }, async ({ action, algorithm, input_data, key, mode }) => {
        try {
            // Input validation
            if (!input_data || input_data.trim().length === 0) {
                throw new Error("Input data cannot be empty or contain only whitespace");
            }
            // For encryption operations, validate key strength
            if ((action === "encrypt" || action === "decrypt")) {
                const actualKey = key || "default-password";
                if (actualKey === "default-password") {
                    throw new Error("Key is required for encryption/decryption operations. Please provide a secure key.");
                }
                if (actualKey.trim().length < 8) {
                    throw new Error("Key must be at least 8 characters long for security");
                }
            }
            // Input size limits for security and performance
            const maxInputSize = 10 * 1024 * 1024; // 10MB limit
            if (input_data.length > maxInputSize) {
                throw new Error(`Input data too large. Maximum size is ${maxInputSize / (1024 * 1024)}MB`);
            }
            // Performance warnings
            if (input_data.length > 1000000) { // 1MB
                console.warn(`WARNING: Input data is large (${Math.round(input_data.length / 1024)}KB), this may impact performance`);
            }
            let result = "";
            let key_info = { algorithm, key_size: 256 };
            if (mode)
                key_info.mode = mode;
            // Get validated key for encryption/decryption operations
            const validatedKey = (action === "encrypt" || action === "decrypt") ? key : (key || "default-password");
            switch (action) {
                case "encrypt":
                    if (algorithm === "aes") {
                        const { key: aesKey, iv, salt } = generateAESKeyAndIV(validatedKey);
                        const cipher = crypto.createCipheriv(`aes-256-${mode.toUpperCase()}`, aesKey, iv);
                        let encrypted = cipher.update(input_data, "utf8", "hex");
                        encrypted += cipher.final("hex");
                        // Store salt and IV with encrypted data for proper decryption
                        result = `${salt.toString("hex")}:${iv.toString("hex")}:${encrypted}`;
                        key_info.iv = iv.toString("hex");
                        key_info.salt = salt.toString("hex");
                        key_info.key_size = 256;
                    }
                    else if (algorithm === "rsa") {
                        const { publicKey } = getOrGenerateRSAKeyPair();
                        const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(input_data, "utf8"));
                        result = encrypted.toString("base64");
                        key_info.key_size = 2048;
                    }
                    break;
                case "decrypt":
                    if (algorithm === "aes") {
                        // Parse salt, IV, and encrypted data from the input
                        const parts = input_data.split(":");
                        if (parts.length !== 3) {
                            throw new Error("Invalid encrypted data format. Expected format: salt:iv:encrypted_data");
                        }
                        const [saltHex, ivHex, encryptedData] = parts;
                        const salt = Buffer.from(saltHex, "hex");
                        const iv = Buffer.from(ivHex, "hex");
                        const { key: aesKey } = generateAESKeyAndIV(validatedKey, salt);
                        const decipher = crypto.createDecipheriv(`aes-256-${mode.toUpperCase()}`, aesKey, iv);
                        let decrypted = decipher.update(encryptedData, "hex", "utf8");
                        decrypted += decipher.final("utf8");
                        result = decrypted;
                    }
                    else if (algorithm === "rsa") {
                        const { privateKey } = getOrGenerateRSAKeyPair();
                        const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(input_data, "base64"));
                        result = decrypted.toString("utf8");
                    }
                    break;
                case "hash":
                    // Warning about MD5 being cryptographically broken
                    if (algorithm === "md5") {
                        console.warn("WARNING: MD5 is cryptographically broken and should not be used for security purposes");
                    }
                    result = crypto.createHash(algorithm).update(input_data).digest("hex");
                    key_info.key_size = algorithm === "sha256" ? 256 : algorithm === "sha512" ? 512 : 128;
                    break;
                case "sign":
                    const { privateKey, publicKey } = getOrGenerateRSAKeyPair();
                    const sign = crypto.createSign('SHA256');
                    sign.update(input_data);
                    sign.end();
                    const signature = sign.sign(privateKey, 'hex');
                    // Return both signature and public key for verification
                    result = `${publicKey}:${signature}`;
                    key_info.key_size = 2048;
                    break;
                case "verify":
                    if (!key)
                        throw new Error("Public key and signature are required for verification");
                    // Parse public key and signature from the input
                    const verifyParts = key.split(":");
                    if (verifyParts.length !== 2) {
                        throw new Error("Invalid signature format. Expected format: public_key:signature");
                    }
                    const [publicKeyPem, signatureToVerify] = verifyParts;
                    const verify = crypto.createVerify('SHA256');
                    verify.update(input_data);
                    verify.end();
                    const isValid = verify.verify(publicKeyPem, signatureToVerify, 'hex');
                    result = isValid ? "Signature is valid" : "Signature is invalid";
                    key_info.key_size = 2048;
                    break;
                case "generate_key":
                    if (algorithm === "aes") {
                        const { key: aesKey, iv } = generateAESKeyAndIV(key || "generated-password");
                        result = `AES Key: ${aesKey.toString("hex")}\nIV: ${iv.toString("hex")}`;
                        key_info.key_size = 256;
                        key_info.iv = iv.toString("hex");
                    }
                    else if (algorithm === "rsa") {
                        const { publicKey, privateKey } = generateRSAKeyPair();
                        result = `Public Key:\n${publicKey}\n\nPrivate Key:\n${privateKey}`;
                        key_info.key_size = 2048;
                    }
                    break;
            }
            // Truncate result for display if too long
            const displayResult = result.length > 200 ? result.substring(0, 200) + "..." : result;
            return {
                content: createContent(`Encryption ${action} completed successfully using ${algorithm.toUpperCase()}`),
                structuredContent: {
                    success: true,
                    message: `Encryption ${action} completed successfully`,
                    result: displayResult,
                    full_result: result,
                    result_length: result.length,
                    key_info
                }
            };
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            const errorType = error instanceof Error ? error.constructor.name : 'UnknownError';
            // Log error for debugging
            console.error(`Encryption tool error [${errorType}]:`, errorMessage);
            return {
                content: createContent(`Encryption operation failed: ${errorMessage}`),
                structuredContent: {
                    success: false,
                    message: `Encryption operation failed: ${errorMessage}`,
                    error_type: errorType,
                    timestamp: new Date().toISOString()
                }
            };
        }
    });
}
