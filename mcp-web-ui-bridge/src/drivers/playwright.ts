/**
 * Playwright driver implementation for desktop browser automation
 */

import { chromium, Browser, BrowserContext, Page, Locator } from 'playwright';
import { Driver, DriverConfig, StreamHandle } from './driver-bridge';
import { DriverUtils } from './driver-bridge';

export class PlaywrightDriver implements Driver {
  private browser: Browser | null = null;
  private context: BrowserContext | null = null;
  private page: Page | null = null;
  private config: DriverConfig;
  private streamHandle: StreamHandle | null = null;

  constructor(config: DriverConfig) {
    this.config = config;
  }

  async open(url: string): Promise<void> {
    if (!this.browser) {
      this.browser = await chromium.launch({
        headless: this.config.headless ?? false,
        slowMo: this.config.slowMo ?? 100,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-accelerated-2d-canvas',
          '--no-first-run',
          '--no-zygote',
          '--disable-gpu'
        ]
      });
    }

    if (!this.context) {
      this.context = await this.browser.newContext({
        viewport: { width: 1280, height: 720 },
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
      });
    }

    this.page = await this.context.newPage();
    await this.page.goto(url, { waitUntil: 'networkidle' });
  }

  async ensureLogin(loginSignalSelector: string, timeoutMs: number): Promise<void> {
    if (!this.page) throw new Error('Page not initialized');

    try {
      await DriverUtils.waitForElementWithRetry(this, loginSignalSelector, timeoutMs);
    } catch (error) {
      // If login signal not found, assume already logged in or needs manual intervention
      console.log('Login signal not found, assuming already authenticated or needs manual login');
    }
  }

  async fill(selector: string, text: string): Promise<void> {
    if (!this.page) throw new Error('Page not initialized');

    const element = this.page.locator(selector);
    await element.waitFor({ state: 'visible', timeout: 10000 });
    await element.clear();
    await element.fill(text);
  }

  async click(selector: string): Promise<void> {
    if (!this.page) throw new Error('Page not initialized');

    const element = this.page.locator(selector);
    await element.waitFor({ state: 'visible', timeout: 10000 });
    await element.click();
  }

  async press(key: string): Promise<void> {
    if (!this.page) throw new Error('Page not initialized');

    await this.page.keyboard.press(key);
  }

  async streamText(
    containerSelector: string,
    onDelta: (text: string) => void,
    timeoutMs: number
  ): Promise<string> {
    if (!this.page) throw new Error('Page not initialized');

    return new Promise((resolve, reject) => {
      let lastText = '';
      let timeoutId: NodeJS.Timeout;
      let mutationObserver: any;

      const cleanup = () => {
        if (timeoutId) clearTimeout(timeoutId);
        if (mutationObserver) mutationObserver.disconnect();
      };

      // Set up timeout
      timeoutId = setTimeout(() => {
        cleanup();
        resolve(lastText);
      }, timeoutMs);

      // Inject mutation observer script
      this.page!.evaluate((selector) => {
        const container = document.querySelector(selector);
        if (!container) return;

        let currentText = container.textContent || '';
        let lastSentLength = 0;

        const observer = new MutationObserver(() => {
          const newText = container.textContent || '';
          if (newText !== currentText) {
            currentText = newText;
            const delta = newText.slice(lastSentLength);
            if (delta) {
              window.dispatchEvent(new CustomEvent('textDelta', { detail: delta }));
              lastSentLength = newText.length;
            }
          }
        });

        observer.observe(container, {
          childList: true,
          subtree: true,
          characterData: true
        });

        // Store observer reference for cleanup
        (window as any).__mutationObserver = observer;

        // Send initial text if any
        if (currentText) {
          window.dispatchEvent(new CustomEvent('textDelta', { detail: currentText }));
          lastSentLength = currentText.length;
        }
      }, containerSelector);

      // Listen for text deltas
      this.page!.on('console', (msg) => {
        if (msg.type() === 'log' && msg.text().startsWith('TEXT_DELTA:')) {
          const delta = msg.text().substring(11);
          onDelta(delta);
          lastText += delta;
        }
      });

      // Listen for custom events
      this.page!.exposeFunction('onTextDelta', (delta: string) => {
        onDelta(delta);
        lastText += delta;
      });

      // Check for completion periodically
      const checkCompletion = async () => {
        try {
          const container = this.page!.locator(containerSelector);
          const currentText = await container.textContent();
          
          if (currentText && currentText !== lastText) {
            const delta = currentText.slice(lastText.length);
            if (delta) {
              onDelta(delta);
              lastText = currentText;
            }
          }

          // Check if response is complete (no typing indicators, etc.)
          const isComplete = await this.page!.evaluate((selector) => {
            const container = document.querySelector(selector);
            if (!container) return true;

            // Look for typing indicators or incomplete markers
            const typingIndicators = container.querySelectorAll('[data-testid*="typing"], .typing, .loading');
            return typingIndicators.length === 0;
          }, containerSelector);

          if (isComplete && lastText.length > 0) {
            cleanup();
            resolve(lastText);
            return;
          }

          // Continue checking
          setTimeout(checkCompletion, 1000);
        } catch (error) {
          cleanup();
          reject(error);
        }
      };

      // Start completion checking
      setTimeout(checkCompletion, 2000);
    });
  }

  async waitFor(
    selOrText: { selector?: string; textContains?: string },
    timeoutMs: number
  ): Promise<void> {
    if (!this.page) throw new Error('Page not initialized');

    if (selOrText.selector) {
      const element = this.page.locator(selOrText.selector);
      await element.waitFor({ state: 'visible', timeout: timeoutMs });
    } else if (selOrText.textContains) {
      await this.page.waitForFunction(
        (text) => document.body.textContent?.includes(text),
        selOrText.textContains,
        { timeout: timeoutMs }
      );
    }
  }

  async close(): Promise<void> {
    if (this.streamHandle) {
      this.streamHandle.close();
      this.streamHandle = null;
    }

    if (this.page) {
      await this.page.close();
      this.page = null;
    }

    if (this.context) {
      await this.context.close();
      this.context = null;
    }

    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
  }

  async screenshot(): Promise<Buffer> {
    if (!this.page) throw new Error('Page not initialized');
    return await this.page.screenshot({ fullPage: true });
  }

  async getText(selector: string): Promise<string> {
    if (!this.page) throw new Error('Page not initialized');
    const element = this.page.locator(selector);
    return await element.textContent() || '';
  }

  async isVisible(selector: string): Promise<boolean> {
    if (!this.page) throw new Error('Page not initialized');
    const element = this.page.locator(selector);
    try {
      await element.waitFor({ state: 'visible', timeout: 1000 });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Save browser state for session persistence
   */
  async saveState(path: string): Promise<void> {
    if (!this.context) throw new Error('Context not initialized');
    await this.context.storageState({ path });
  }

  /**
   * Load browser state for session restoration
   */
  async loadState(path: string): Promise<void> {
    if (!this.context) throw new Error('Context not initialized');
    // Note: storageState can only be set during context creation
    // This would require recreating the context with the saved state
    console.warn('Loading state requires context recreation - implement in open() method');
  }
}
