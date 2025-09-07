/**
 * Appium driver implementation for mobile browser/app automation
 */

import { remote, RemoteOptions, Browser } from 'webdriverio';
import { Driver, DriverConfig, StreamHandle } from './driver-bridge';
import { DriverUtils } from './driver-bridge';

export class AppiumDriver implements Driver {
  private driver: Browser | null = null;
  private config: DriverConfig;
  private streamHandle: StreamHandle | null = null;

  constructor(config: DriverConfig) {
    this.config = config;
  }

  async open(url: string): Promise<void> {
    const options: RemoteOptions = {
      hostname: 'localhost',
      port: 4723,
      path: '/',
      capabilities: this.getCapabilities(),
      logLevel: 'error' as any
    };

    this.driver = await remote(options);
    await this.driver.url(url);
  }

  private getCapabilities(): any {
    const { platform, deviceName } = this.config;
    
    if (platform === 'android') {
      return {
        platformName: 'Android',
        'appium:deviceName': deviceName || 'emulator-5554',
        'appium:automationName': 'UiAutomator2',
        'appium:browserName': 'Chrome',
        'appium:chromedriverExecutable': undefined, // Use system ChromeDriver
        'appium:newCommandTimeout': 300,
        'appium:autoGrantPermissions': true,
        'appium:noReset': true,
        'appium:fullReset': false
      };
    } else if (platform === 'ios') {
      return {
        platformName: 'iOS',
        'appium:deviceName': deviceName || 'iPhone 15 Pro',
        'appium:automationName': 'XCUITest',
        'appium:browserName': 'Safari',
        'appium:newCommandTimeout': 300,
        'appium:autoAcceptAlerts': true,
        'appium:noReset': true,
        'appium:fullReset': false
      };
    }

    throw new Error(`Unsupported platform: ${platform}`);
  }

  async ensureLogin(loginSignalSelector: string, timeoutMs: number): Promise<void> {
    if (!this.driver) throw new Error('Driver not initialized');

    try {
      await DriverUtils.waitForElementWithRetry(this, loginSignalSelector, timeoutMs);
    } catch (error) {
      console.log('Login signal not found, assuming already authenticated or needs manual login');
    }
  }

  async fill(selector: string, text: string): Promise<void> {
    if (!this.driver) throw new Error('Driver not initialized');

    const element = await this.driver.$(selector);
    await element.waitForDisplayed({ timeout: 10000 });
    await element.clearValue();
    await element.setValue(text);
  }

  async click(selector: string): Promise<void> {
    if (!this.driver) throw new Error('Driver not initialized');

    const element = await this.driver.$(selector);
    await element.waitForDisplayed({ timeout: 10000 });
    await element.click();
  }

  async press(key: string): Promise<void> {
    if (!this.driver) throw new Error('Driver not initialized');

    // Map common keys to mobile equivalents
    const keyMap: Record<string, string> = {
      'Enter': '\n',
      'Tab': '\t',
      'Escape': '\uE00C', // Appium key code
      'Backspace': '\uE003',
      'Delete': '\uE017'
    };

    const mobileKey = keyMap[key] || key;
    await this.driver.keys(mobileKey);
  }

  async streamText(
    containerSelector: string,
    onDelta: (text: string) => void,
    timeoutMs: number
  ): Promise<string> {
    if (!this.driver) throw new Error('Driver not initialized');

    return new Promise((resolve, reject) => {
      let lastText = '';
      let timeoutId: NodeJS.Timeout;
      let pollInterval: NodeJS.Timeout;

      const cleanup = () => {
        if (timeoutId) clearTimeout(timeoutId);
        if (pollInterval) clearInterval(pollInterval);
      };

      // Set up timeout
      timeoutId = setTimeout(() => {
        cleanup();
        resolve(lastText);
      }, timeoutMs);

      // Poll for text changes
      const pollForText = async () => {
        try {
          const element = await this.driver!.$(containerSelector);
          const currentText = await element.getText();
          
          if (currentText && currentText !== lastText) {
            const delta = currentText.slice(lastText.length);
            if (delta) {
              onDelta(delta);
              lastText = currentText;
            }
          }

          // Check if response is complete
          const isComplete = await this.isResponseComplete(containerSelector);
          if (isComplete && lastText.length > 0) {
            cleanup();
            resolve(lastText);
            return;
          }
        } catch (error) {
          cleanup();
          reject(error);
        }
      };

      // Start polling
      pollInterval = setInterval(pollForText, 1000);
      
      // Initial poll
      setTimeout(pollForText, 2000);
    });
  }

  private async isResponseComplete(containerSelector: string): Promise<boolean> {
    if (!this.driver) return true;

    try {
      // Look for typing indicators or loading states
      const typingIndicators = await this.driver.$$('[data-testid*="typing"], .typing, .loading');
      return typingIndicators.length === 0;
    } catch {
      return true;
    }
  }

  async waitFor(
    selOrText: { selector?: string; textContains?: string },
    timeoutMs: number
  ): Promise<void> {
    if (!this.driver) throw new Error('Driver not initialized');

    if (selOrText.selector) {
      const element = await this.driver.$(selOrText.selector);
      await element.waitForDisplayed({ timeout: timeoutMs });
    } else if (selOrText.textContains) {
      // Wait for text to appear in page source
      await this.driver.waitUntil(
        async () => {
          const pageSource = await this.driver!.getPageSource();
          return pageSource.includes(selOrText.textContains!);
        },
        { timeout: timeoutMs }
      );
    }
  }

  async close(): Promise<void> {
    if (this.streamHandle) {
      this.streamHandle.close();
      this.streamHandle = null;
    }

    if (this.driver) {
      await this.driver.deleteSession();
      this.driver = null;
    }
  }

  // Mobile-specific methods
  async tap(x: number, y: number): Promise<void> {
    if (!this.driver) throw new Error('Driver not initialized');
    await this.driver.touchAction({
      action: 'tap',
      x,
      y
    });
  }

  async swipe(
    from: { x: number; y: number },
    to: { x: number; y: number },
    duration: number = 1000
  ): Promise<void> {
    if (!this.driver) throw new Error('Driver not initialized');
    await this.driver.touchAction([
      { action: 'press', x: from.x, y: from.y },
      { action: 'wait', ms: duration },
      { action: 'moveTo', x: to.x, y: to.y },
      { action: 'release' }
    ]);
  }

  async screenshot(): Promise<Buffer> {
    if (!this.driver) throw new Error('Driver not initialized');
    const screenshot = await this.driver.takeScreenshot();
    return Buffer.from(screenshot, 'base64');
  }

  async getText(selector: string): Promise<string> {
    if (!this.driver) throw new Error('Driver not initialized');
    const element = await this.driver.$(selector);
    return await element.getText();
  }

  async isVisible(selector: string): Promise<boolean> {
    if (!this.driver) throw new Error('Driver not initialized');
    try {
      const element = await this.driver.$(selector);
      return await element.isDisplayed();
    } catch {
      return false;
    }
  }

  /**
   * Get device info
   */
  async getDeviceInfo(): Promise<any> {
    if (!this.driver) throw new Error('Driver not initialized');
    return await this.driver.getSession();
  }

  /**
   * Switch to web context (for hybrid apps)
   */
  async switchToWebContext(): Promise<void> {
    if (!this.driver) throw new Error('Driver not initialized');
    const contexts = await this.driver.getContexts();
    const webContext = contexts.find(ctx => ctx.includes('WEBVIEW'));
    if (webContext) {
      await this.driver.switchContext(webContext);
    }
  }

  /**
   * Switch to native context
   */
  async switchToNativeContext(): Promise<void> {
    if (!this.driver) throw new Error('Driver not initialized');
    await this.driver.switchContext('NATIVE_APP');
  }
}
