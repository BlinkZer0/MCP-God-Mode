/**
 * Unified driver interface for browser/app automation
 * Abstracts Playwright (desktop) and Appium (mobile) implementations
 */

export interface StreamHandle {
  close(): void;
}

export interface Driver {
  open(url: string): Promise<void>;
  ensureLogin(loginSignalSelector: string, timeoutMs: number): Promise<void>;
  fill(selector: string, text: string): Promise<void>;
  click(selector: string): Promise<void>;
  press(key: string): Promise<void>;
  streamText(
    containerSelector: string,
    onDelta: (text: string) => void,
    timeoutMs: number
  ): Promise<string>;
  waitFor(
    selOrText: { selector?: string; textContains?: string },
    timeoutMs: number
  ): Promise<void>;
  close(): Promise<void>;
  // Mobile-specific methods
  tap?(x: number, y: number): Promise<void>;
  swipe?(from: { x: number; y: number }, to: { x: number; y: number }, duration?: number): Promise<void>;
  // Utility methods
  screenshot?(): Promise<Buffer>;
  getText?(selector: string): Promise<string>;
  isVisible?(selector: string): Promise<boolean>;
}

export type Platform = "desktop" | "android" | "ios";

export interface DriverConfig {
  platform: Platform;
  headless?: boolean;
  slowMo?: number;
  timeout?: number;
  // Mobile-specific
  deviceName?: string;
  appiumUrl?: string;
}

/**
 * Factory function to get the appropriate driver based on platform
 */
export async function getDriver(config: DriverConfig): Promise<Driver> {
  const { platform } = config;
  
  switch (platform) {
    case "desktop":
      const { PlaywrightDriver } = await import("./playwright");
      return new PlaywrightDriver(config);
    
    case "android":
    case "ios":
      const { AppiumDriver } = await import("./appium");
      return new AppiumDriver(config);
    
    default:
      throw new Error(`Unsupported platform: ${platform}`);
  }
}

/**
 * Get driver from environment variables
 */
export async function getDriverFromEnv(): Promise<Driver> {
  const platform = (process.env.PLATFORM as Platform) || "desktop";
  const headless = process.env.PLAYWRIGHT_HEADLESS === "true";
  const slowMo = parseInt(process.env.PLAYWRIGHT_SLOW_MO || "100");
  const deviceName = process.env.ANDROID_DEVICE_NAME || process.env.IOS_DEVICE_NAME;
  const appiumUrl = process.env.APPIUM_SERVER_URL || "http://localhost:4723";
  
  return getDriver({
    platform,
    headless,
    slowMo,
    deviceName,
    appiumUrl
  });
}

/**
 * Common utility functions for all drivers
 */
export class DriverUtils {
  /**
   * Normalize selector to be more stable
   */
  static normalizeSelector(selector: string): string {
    // Prefer data-testid, then role, then fallback to original
    if (selector.includes('data-testid')) return selector;
    if (selector.includes('[role=')) return selector;
    return selector;
  }

  /**
   * Wait for element with retries and fuzzy matching
   */
  static async waitForElementWithRetry(
    driver: Driver,
    selector: string,
    timeoutMs: number = 10000,
    retries: number = 3
  ): Promise<void> {
    for (let i = 0; i < retries; i++) {
      try {
        await driver.waitFor({ selector }, timeoutMs / retries);
        return;
      } catch (error) {
        if (i === retries - 1) throw error;
        // Try fuzzy alternatives
        const alternatives = this.getFuzzySelectors(selector);
        for (const alt of alternatives) {
          try {
            await driver.waitFor({ selector: alt }, 1000);
            return;
          } catch {
            // Continue to next alternative
          }
        }
      }
    }
  }

  /**
   * Generate fuzzy selector alternatives
   */
  private static getFuzzySelectors(selector: string): string[] {
    const alternatives: string[] = [];
    
    // If it's a data-testid, try without it
    if (selector.includes('data-testid')) {
      alternatives.push(selector.replace(/\[data-testid[^\]]*\]/g, ''));
    }
    
    // Try role-based selectors
    if (selector.includes('textarea')) {
      alternatives.push('textarea');
      alternatives.push('[role="textbox"]');
    }
    
    if (selector.includes('button')) {
      alternatives.push('button');
      alternatives.push('[role="button"]');
    }
    
    return alternatives;
  }

  /**
   * Safe text substitution for variables
   */
  static substituteVariables(text: string, variables: Record<string, string>): string {
    return text.replace(/\$\{([^}]+)\}/g, (match, key) => {
      return variables[key] || match;
    });
  }
}
