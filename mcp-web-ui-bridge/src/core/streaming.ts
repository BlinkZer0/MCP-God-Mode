/**
 * Text streaming functionality for real-time AI response capture
 * Handles DOM mutation observation and mobile text polling
 */

import { Driver } from '../drivers/driver-bridge';

export interface StreamOptions {
  timeoutMs: number;
  pollInterval?: number;
  completionSignals?: string[];
  maxRetries?: number;
}

export interface StreamResult {
  text: string;
  isComplete: boolean;
  metadata?: {
    duration: number;
    chunks: number;
    finalChunkSize: number;
  };
}

export class TextStreamer {
  private options: StreamOptions;
  private isStreaming = false;
  private streamHandle: StreamHandle | null = null;

  constructor(options: StreamOptions) {
    this.options = {
      pollInterval: 1000,
      completionSignals: ['typing', 'loading', 'thinking'],
      maxRetries: 3,
      ...options
    };
  }

  /**
   * Stream text from a container with real-time updates
   */
  async streamText(
    driver: Driver,
    containerSelector: string,
    onDelta: (text: string) => void
  ): Promise<StreamResult> {
    if (this.isStreaming) {
      throw new Error('Already streaming');
    }

    this.isStreaming = true;
    const startTime = Date.now();
    let lastText = '';
    let chunks = 0;
    let retries = 0;

    try {
      // Platform-specific streaming implementation
      if (this.isDesktopDriver(driver)) {
        return await this.streamFromDesktop(driver, containerSelector, onDelta, startTime);
      } else {
        return await this.streamFromMobile(driver, containerSelector, onDelta, startTime);
      }
    } finally {
      this.isStreaming = false;
    }
  }

  private isDesktopDriver(driver: Driver): boolean {
    // Check if driver has Playwright-specific methods
    return 'evaluate' in driver || 'locator' in driver;
  }

  /**
   * Desktop streaming using DOM mutation observer
   */
  private async streamFromDesktop(
    driver: Driver,
    containerSelector: string,
    onDelta: (text: string) => void,
    startTime: number
  ): Promise<StreamResult> {
    return new Promise((resolve, reject) => {
      let lastText = '';
      let chunks = 0;
      let timeoutId: NodeJS.Timeout;
      let checkInterval: NodeJS.Timeout;

      const cleanup = () => {
        if (timeoutId) clearTimeout(timeoutId);
        if (checkInterval) clearInterval(checkInterval);
      };

      // Set up timeout
      timeoutId = setTimeout(() => {
        cleanup();
        resolve({
          text: lastText,
          isComplete: false,
          metadata: {
            duration: Date.now() - startTime,
            chunks,
            finalChunkSize: lastText.length
          }
        });
      }, this.options.timeoutMs);

      // Inject mutation observer script
      (driver as any).evaluate((selector: string) => {
        const container = document.querySelector(selector);
        if (!container) return;

        let currentText = container.textContent || '';
        let lastSentLength = 0;

        const observer = new MutationObserver(() => {
          const newText = container.textContent || '';
          if (newText !== currentText) {
            currentText = newText;
            const delta = newText.slice(lastSentLength);
            if (delta.trim()) {
              // Send delta through custom event
              window.dispatchEvent(new CustomEvent('textStreamDelta', { 
                detail: { delta, fullText: newText } 
              }));
              lastSentLength = newText.length;
            }
          }
        });

        observer.observe(container, {
          childList: true,
          subtree: true,
          characterData: true,
          attributes: false
        });

        // Store observer for cleanup
        (window as any).__textStreamObserver = observer;

        // Send initial text if any
        if (currentText.trim()) {
          window.dispatchEvent(new CustomEvent('textStreamDelta', { 
            detail: { delta: currentText, fullText: currentText } 
          }));
          lastSentLength = currentText.length;
        }
      }, containerSelector);

      // Listen for text deltas
      (driver as any).on('console', (msg: any) => {
        if (msg.type() === 'log' && msg.text().startsWith('TEXT_STREAM:')) {
          const data = JSON.parse(msg.text().substring(12));
          onDelta(data.delta);
          lastText = data.fullText;
          chunks++;
        }
      });

      // Check for completion
      const checkCompletion = async () => {
        try {
          const isComplete = await this.checkCompletion(driver, containerSelector);
          if (isComplete && lastText.length > 0) {
            cleanup();
            resolve({
              text: lastText,
              isComplete: true,
              metadata: {
                duration: Date.now() - startTime,
                chunks,
                finalChunkSize: lastText.length
              }
            });
            return;
          }

          // Continue checking
          setTimeout(checkCompletion, this.options.pollInterval);
        } catch (error) {
          cleanup();
          reject(error);
        }
      };

      // Start completion checking
      setTimeout(checkCompletion, 2000);
    });
  }

  /**
   * Mobile streaming using polling
   */
  private async streamFromMobile(
    driver: Driver,
    containerSelector: string,
    onDelta: (text: string) => void,
    startTime: number
  ): Promise<StreamResult> {
    return new Promise((resolve, reject) => {
      let lastText = '';
      let chunks = 0;
      let timeoutId: NodeJS.Timeout;
      let pollInterval: NodeJS.Timeout;

      const cleanup = () => {
        if (timeoutId) clearTimeout(timeoutId);
        if (pollInterval) clearInterval(pollInterval);
      };

      // Set up timeout
      timeoutId = setTimeout(() => {
        cleanup();
        resolve({
          text: lastText,
          isComplete: false,
          metadata: {
            duration: Date.now() - startTime,
            chunks,
            finalChunkSize: lastText.length
          }
        });
      }, this.options.timeoutMs);

      // Poll for text changes
      const pollForText = async () => {
        try {
          const currentText = await driver.getText(containerSelector);
          
          if (currentText && currentText !== lastText) {
            const delta = currentText.slice(lastText.length);
            if (delta.trim()) {
              onDelta(delta);
              lastText = currentText;
              chunks++;
            }
          }

          // Check if response is complete
          const isComplete = await this.checkCompletion(driver, containerSelector);
          if (isComplete && lastText.length > 0) {
            cleanup();
            resolve({
              text: lastText,
              isComplete: true,
              metadata: {
                duration: Date.now() - startTime,
                chunks,
                finalChunkSize: lastText.length
              }
            });
            return;
          }
        } catch (error) {
          cleanup();
          reject(error);
        }
      };

      // Start polling
      pollInterval = setInterval(pollForText, this.options.pollInterval);
      
      // Initial poll
      setTimeout(pollForText, 2000);
    });
  }

  /**
   * Check if the response is complete
   */
  private async checkCompletion(driver: Driver, containerSelector: string): Promise<boolean> {
    try {
      // Look for completion signals
      for (const signal of this.options.completionSignals || []) {
        const selectors = [
          `[data-testid*="${signal}"]`,
          `.${signal}`,
          `[class*="${signal}"]`,
          `[aria-label*="${signal}"]`
        ];

        for (const selector of selectors) {
          try {
            const isVisible = await driver.isVisible(selector);
            if (isVisible) {
              return false; // Still processing
            }
          } catch {
            // Continue checking other selectors
          }
        }
      }

      // Check for stable text (no changes in last few seconds)
      const currentText = await driver.getText(containerSelector);
      if (currentText && currentText.length > 0) {
        // Additional heuristics for completion
        const hasEndingPunctuation = /[.!?]$/.test(currentText.trim());
        const hasMinimumLength = currentText.length > 10;
        
        return hasEndingPunctuation && hasMinimumLength;
      }

      return false;
    } catch (error) {
      console.warn('Error checking completion:', error);
      return true; // Assume complete on error
    }
  }

  /**
   * Stop streaming
   */
  stop(): void {
    this.isStreaming = false;
    if (this.streamHandle) {
      this.streamHandle.close();
      this.streamHandle = null;
    }
  }
}

export interface StreamHandle {
  close(): void;
}

/**
 * Utility functions for text processing
 */
export class TextProcessor {
  /**
   * Clean and normalize text
   */
  static cleanText(text: string): string {
    return text
      .replace(/\s+/g, ' ') // Normalize whitespace
      .replace(/\n\s*\n/g, '\n') // Remove empty lines
      .trim();
  }

  /**
   * Extract meaningful deltas (ignore whitespace-only changes)
   */
  static extractDelta(oldText: string, newText: string): string {
    const delta = newText.slice(oldText.length);
    return delta.trim() ? delta : '';
  }

  /**
   * Detect if text appears to be complete
   */
  static isCompleteResponse(text: string): boolean {
    if (!text || text.length < 10) return false;
    
    // Check for ending punctuation
    const hasEndingPunctuation = /[.!?]$/.test(text.trim());
    
    // Check for common completion patterns
    const completionPatterns = [
      /thank you/i,
      /let me know if/i,
      /is there anything else/i,
      /hope this helps/i
    ];
    
    const hasCompletionPattern = completionPatterns.some(pattern => pattern.test(text));
    
    return hasEndingPunctuation || hasCompletionPattern;
  }
}
