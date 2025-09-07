/**
 * Encrypted session storage and management
 * Handles Playwright storageState and Appium session persistence
 */

import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'crypto';
import { promisify } from 'util';
import * as fs from 'fs-extra';
import * as path from 'path';
import * as keytar from 'keytar';
import { Driver } from '../drivers/driver-bridge';

const scryptAsync = promisify(scrypt);

export interface SessionData {
  provider: string;
  platform: string;
  storageState?: any; // Playwright storageState
  sessionCapabilities?: any; // Appium session capabilities
  cookies?: any[];
  localStorage?: Record<string, string>;
  sessionStorage?: Record<string, string>;
  timestamp: number;
  expiresAt?: number;
}

export class SessionManager {
  private storagePath: string;
  private encryptionKey: Buffer | null = null;
  private keyService = 'mcp-web-ui-bridge';
  private keyAccount = 'session-encryption';

  constructor(storagePath: string = './sessions') {
    this.storagePath = storagePath;
  }

  /**
   * Initialize encryption key from environment or OS keychain
   */
  async initializeEncryption(): Promise<void> {
    const envKey = process.env.ENCRYPTION_KEY;
    
    if (envKey) {
      this.encryptionKey = await this.deriveKey(envKey);
    } else {
      // Try to get from OS keychain
      try {
        const storedKey = await keytar.getPassword(this.keyService, this.keyAccount);
        if (storedKey) {
          this.encryptionKey = await this.deriveKey(storedKey);
        } else {
          // Generate new key and store in keychain
          const newKey = randomBytes(32).toString('hex');
          await keytar.setPassword(this.keyService, this.keyAccount, newKey);
          this.encryptionKey = await this.deriveKey(newKey);
        }
      } catch (error) {
        console.warn('Could not access OS keychain, using temporary key:', error);
        // Fallback to temporary key (not persisted)
        this.encryptionKey = randomBytes(32);
      }
    }
  }

  private async deriveKey(password: string): Promise<Buffer> {
    const salt = Buffer.from('mcp-web-ui-bridge-salt', 'utf8');
    return (await scryptAsync(password, salt, 32)) as Buffer;
  }

  /**
   * Encrypt session data
   */
  private async encrypt(data: any): Promise<string> {
    if (!this.encryptionKey) {
      await this.initializeEncryption();
    }

    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-gcm', this.encryptionKey!, iv);
    
    const jsonData = JSON.stringify(data);
    let encrypted = cipher.update(jsonData, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return JSON.stringify({
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      encrypted
    });
  }

  /**
   * Decrypt session data
   */
  private async decrypt(encryptedData: string): Promise<any> {
    if (!this.encryptionKey) {
      await this.initializeEncryption();
    }

    const { iv, authTag, encrypted } = JSON.parse(encryptedData);
    
    const decipher = createDecipheriv('aes-256-gcm', this.encryptionKey!, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return JSON.parse(decrypted);
  }

  /**
   * Save session data for a provider
   */
  async saveSession(provider: string, platform: string, data: Partial<SessionData>): Promise<void> {
    await fs.ensureDir(this.storagePath);
    
    const sessionData: SessionData = {
      provider,
      platform,
      timestamp: Date.now(),
      ...data
    };

    const encryptedData = await this.encrypt(sessionData);
    const filePath = path.join(this.storagePath, `${provider}-${platform}.session`);
    
    await fs.writeFile(filePath, encryptedData, 'utf8');
  }

  /**
   * Load session data for a provider
   */
  async loadSession(provider: string, platform: string): Promise<SessionData | null> {
    const filePath = path.join(this.storagePath, `${provider}-${platform}.session`);
    
    try {
      if (!(await fs.pathExists(filePath))) {
        return null;
      }

      const encryptedData = await fs.readFile(filePath, 'utf8');
      const sessionData = await this.decrypt(encryptedData);
      
      // Check if session is expired
      if (sessionData.expiresAt && Date.now() > sessionData.expiresAt) {
        await this.clearSession(provider, platform);
        return null;
      }

      return sessionData;
    } catch (error) {
      console.warn(`Failed to load session for ${provider}:`, error);
      return null;
    }
  }

  /**
   * Clear session data for a provider
   */
  async clearSession(provider: string, platform: string): Promise<void> {
    const filePath = path.join(this.storagePath, `${provider}-${platform}.session`);
    
    try {
      if (await fs.pathExists(filePath)) {
        await fs.remove(filePath);
      }
    } catch (error) {
      console.warn(`Failed to clear session for ${provider}:`, error);
    }
  }

  /**
   * List all available sessions
   */
  async listSessions(): Promise<Array<{ provider: string; platform: string; timestamp: number }>> {
    await fs.ensureDir(this.storagePath);
    
    const files = await fs.readdir(this.storagePath);
    const sessions: Array<{ provider: string; platform: string; timestamp: number }> = [];
    
    for (const file of files) {
      if (file.endsWith('.session')) {
        try {
          const encryptedData = await fs.readFile(path.join(this.storagePath, file), 'utf8');
          const sessionData = await this.decrypt(encryptedData);
          sessions.push({
            provider: sessionData.provider,
            platform: sessionData.platform,
            timestamp: sessionData.timestamp
          });
        } catch (error) {
          console.warn(`Failed to read session file ${file}:`, error);
        }
      }
    }
    
    return sessions;
  }

  /**
   * Clean up expired sessions
   */
  async cleanupExpiredSessions(): Promise<void> {
    const sessions = await this.listSessions();
    
    for (const session of sessions) {
      const sessionData = await this.loadSession(session.provider, session.platform);
      if (!sessionData || (sessionData.expiresAt && Date.now() > sessionData.expiresAt)) {
        await this.clearSession(session.provider, session.platform);
      }
    }
  }
}

/**
 * Session helpers for different driver types
 */
export class SessionHelpers {
  /**
   * Ensure session is available and valid for a provider
   */
  static async ensureSession(
    sessionManager: SessionManager,
    provider: string,
    platform: string,
    driver: Driver
  ): Promise<void> {
    const sessionData = await sessionManager.loadSession(provider, platform);
    
    if (sessionData) {
      // Restore session state
      if (sessionData.storageState && 'loadState' in driver) {
        await (driver as any).loadState(sessionData.storageState);
      }
      
      if (sessionData.cookies && 'setCookies' in driver) {
        await (driver as any).setCookies(sessionData.cookies);
      }
    }
  }

  /**
   * Save current session state
   */
  static async saveSession(
    sessionManager: SessionManager,
    provider: string,
    platform: string,
    driver: Driver
  ): Promise<void> {
    const sessionData: Partial<SessionData> = {};
    
    // Save Playwright storage state
    if ('saveState' in driver) {
      const statePath = `./temp-${provider}-${platform}-state.json`;
      await (driver as any).saveState(statePath);
      sessionData.storageState = await fs.readJson(statePath);
      await fs.remove(statePath);
    }
    
    // Save cookies
    if ('getCookies' in driver) {
      sessionData.cookies = await (driver as any).getCookies();
    }
    
    // Save local/session storage
    if ('getLocalStorage' in driver) {
      sessionData.localStorage = await (driver as any).getLocalStorage();
    }
    
    if ('getSessionStorage' in driver) {
      sessionData.sessionStorage = await (driver as any).getSessionStorage();
    }
    
    await sessionManager.saveSession(provider, platform, sessionData);
  }
}

// Global session manager instance
export const sessionManager = new SessionManager(
  process.env.SESSION_STORAGE_PATH || './sessions'
);
