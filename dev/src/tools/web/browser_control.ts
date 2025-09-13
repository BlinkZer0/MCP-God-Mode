import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { PLATFORM, IS_WINDOWS, IS_LINUX, IS_MACOS } from "../../config/environment.js";
import { spawn, exec } from "node:child_process";
import { promisify } from "node:util";
import * as fs from "node:fs/promises";
import * as path from "node:path";

// Browser automation imports
import { chromium, firefox, webkit, Browser, BrowserContext, Page } from 'playwright';
import puppeteer, { Browser as PuppeteerBrowser, Page as PuppeteerPage } from 'puppeteer';

const execAsync = promisify(exec);

// Global browser instance tracking
let browserInstances: Map<string, { browser: Browser | PuppeteerBrowser, context?: BrowserContext, page?: Page | PuppeteerPage, type: 'playwright' | 'puppeteer' }> = new Map();

export function registerBrowserControl(server: McpServer) {
  server.registerTool("browser_control", {
    description: "Advanced cross-platform browser automation and control with real browser launching",
    inputSchema: {
      action: z.enum(["launch", "navigate", "click", "type", "screenshot", "execute_script", "close"]).describe("Browser action to perform"),
      browser: z.string().optional().describe("Browser to use (chrome, firefox, safari, edge)"),
      url: z.string().optional().describe("URL to navigate to"),
      selector: z.string().optional().describe("CSS selector for element interaction"),
      text: z.string().optional().describe("Text to type or script to execute"),
      headless: z.boolean().optional().describe("Run browser in headless mode")
    },
    outputSchema: {
      success: z.boolean(),
      message: z.string(),
      result: z.string().optional(),
      browser_instance: z.string().optional(),
      screenshot_path: z.string().optional()
    }
  }, async ({ action, browser = "chrome", url, selector, text, headless = false }) => {
    try {
      let result = "";
      let browserInstance = "";
      let screenshotPath = "";
      
      switch (action) {
        case "launch":
          result = await launchBrowser(browser, headless);
          browserInstance = `browser_${Date.now()}`;
          break;
          
        case "navigate":
          if (!url) throw new Error("URL is required for navigate action");
          result = await navigateToUrl(browser, url, headless);
          break;
          
        case "click":
          if (!selector) throw new Error("Selector is required for click action");
          result = await clickElement(browser, selector);
          break;
          
        case "type":
          if (!text) throw new Error("Text is required for type action");
          result = await typeText(browser, selector, text);
          break;
          
        case "screenshot":
          screenshotPath = await takeScreenshot(browser);
          result = `Screenshot saved to: ${screenshotPath}`;
          break;
          
        case "execute_script":
          if (!text) throw new Error("Script is required for execute_script action");
          result = await executeScript(browser, text);
          break;
          
        case "close":
          result = await closeBrowser(browser);
          break;
      }
      
      return { 
        content: [], 
        structuredContent: { 
          success: true, 
          message: `Browser action ${action} completed successfully`,
          result,
          browser_instance: browserInstance,
          screenshot_path: screenshotPath
        } 
      };
    } catch (error) {
      return { 
        content: [], 
        structuredContent: { 
          success: false, 
          message: `Browser control failed: ${error instanceof Error ? (error as Error).message : 'Unknown error'}` 
        } 
      };
    }
  });
}

// Browser launching functions
async function launchBrowser(browser: string, headless: boolean): Promise<string> {
  const instanceId = `browser_${Date.now()}`;
  
  try {
    // Try Playwright first
    let playwrightBrowser: Browser;
    let context: BrowserContext;
    let page: Page;
    
    try {
      switch (browser.toLowerCase()) {
        case "chrome":
        case "chromium":
          playwrightBrowser = await chromium.launch({ 
            headless,
            args: ['--no-sandbox', '--disable-setuid-sandbox']
          });
          break;
        case "firefox":
          playwrightBrowser = await firefox.launch({ headless });
          break;
        case "safari":
        case "webkit":
          playwrightBrowser = await webkit.launch({ headless });
          break;
        default:
          playwrightBrowser = await chromium.launch({ 
            headless,
            args: ['--no-sandbox', '--disable-setuid-sandbox']
          });
      }
      
      context = await playwrightBrowser.newContext();
      page = await context.newPage();
      
      browserInstances.set(instanceId, {
        browser: playwrightBrowser,
        context,
        page,
        type: 'playwright'
      });
      
      return `${browser} browser launched successfully with Playwright${headless ? ' (headless mode)' : ''}`;
      
    } catch (playwrightError) {
      console.log(`Playwright failed: ${playwrightError}`);
      
      // Skip Puppeteer and go directly to system browser for better reliability
      console.log(`Using system browser fallback for ${browser}`);
      return await launchSystemBrowser(browser);
    }
    
  } catch (error) {
    throw new Error(`Failed to launch ${browser}: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function navigateToUrl(browser: string, url: string, headless: boolean): Promise<string> {
  try {
    // Find the most recent browser instance
    const instances = Array.from(browserInstances.entries());
    if (instances.length === 0) {
      // Launch a new browser if none exists
      await launchBrowser(browser, headless);
    }
    
    // Check if we have a browser instance to navigate with
    if (instances.length > 0) {
      const [instanceId, instance] = instances[instances.length - 1];
      
      if (instance.type === 'playwright') {
        const page = instance.page as Page;
        await page.goto(url);
        return `Navigated to ${url} using Playwright ${browser}`;
      } else {
        const page = instance.page as PuppeteerPage;
        await page.goto(url);
        return `Navigated to ${url} using Puppeteer ${browser}`;
      }
    } else {
      // No browser instance available, try system browser navigation
      return await navigateSystemBrowser(browser, url);
    }
  } catch (error) {
    // If navigation fails, try system browser as fallback
    try {
      return await navigateSystemBrowser(browser, url);
    } catch (systemError) {
      throw new Error(`Failed to navigate to ${url}: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
}

// System browser navigation function
async function navigateSystemBrowser(browser: string, url: string): Promise<string> {
  try {
    let command = "";
    
    switch (browser.toLowerCase()) {
      case "chrome":
      case "chromium":
        if (IS_WINDOWS) {
          command = `"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" "${url}"`;
        } else if (IS_LINUX) {
          command = `google-chrome "${url}"`;
        } else if (IS_MACOS) {
          command = `open -a 'Google Chrome' "${url}"`;
        }
        break;
      case "firefox":
        if (IS_WINDOWS) {
          command = `"C:\\Program Files\\Mozilla Firefox\\firefox.exe" "${url}"`;
        } else if (IS_LINUX) {
          command = `firefox "${url}"`;
        } else if (IS_MACOS) {
          command = `open -a 'Firefox' "${url}"`;
        }
        break;
      case "edge":
        if (IS_WINDOWS) {
          command = `"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" "${url}"`;
        } else if (IS_LINUX) {
          command = `microsoft-edge "${url}"`;
        } else if (IS_MACOS) {
          command = `open -a 'Microsoft Edge' "${url}"`;
        }
        break;
      case "opera":
      case "operagx":
        if (IS_WINDOWS) {
          command = `"C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\Programs\\Opera GX\\121.0.5600.81\\opera.exe" "${url}"`;
        } else if (IS_LINUX) {
          command = `opera "${url}"`;
        } else if (IS_MACOS) {
          command = `open -a 'Opera' "${url}"`;
        }
        break;
      default:
        // Use system default
        if (IS_WINDOWS) {
          command = `start "" "${url}"`;
        } else if (IS_LINUX) {
          command = `xdg-open "${url}"`;
        } else if (IS_MACOS) {
          command = `open "${url}"`;
        }
    }
    
    if (!command) {
      throw new Error(`Unsupported browser: ${browser}`);
    }
    
    // Execute the command
    const child = spawn(command, [], {
      stdio: 'pipe',
      detached: true,
      shell: true
    });
    
    // Don't wait for the process to finish
    child.unref();
    
    return `Navigated to ${url} using system ${browser}`;
    
  } catch (error) {
    throw new Error(`Failed to navigate system browser to ${url}: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function clickElement(browser: string, selector: string): Promise<string> {
  try {
    const instances = Array.from(browserInstances.entries());
    if (instances.length === 0) {
      throw new Error('No browser instance available');
    }
    
    const [instanceId, instance] = instances[instances.length - 1];
    
    if (instance.type === 'playwright') {
      const page = instance.page as Page;
      await page.click(selector);
      return `Element clicked successfully using Playwright: ${selector}`;
    } else {
      const page = instance.page as PuppeteerPage;
      await page.click(selector);
      return `Element clicked successfully using Puppeteer: ${selector}`;
    }
  } catch (error) {
    throw new Error(`Failed to click element ${selector}: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function typeText(browser: string, selector: string | undefined, text: string): Promise<string> {
  try {
    const instances = Array.from(browserInstances.entries());
    if (instances.length === 0) {
      throw new Error('No browser instance available');
    }
    
    const [instanceId, instance] = instances[instances.length - 1];
    
    if (instance.type === 'playwright') {
      const page = instance.page as Page;
      if (selector) {
        await page.fill(selector, text);
        return `Text typed successfully using Playwright: "${text}" in ${selector}`;
      } else {
        await page.keyboard.type(text);
        return `Text typed successfully using Playwright: "${text}"`;
      }
    } else {
      const page = instance.page as PuppeteerPage;
      if (selector) {
        await page.type(selector, text);
        return `Text typed successfully using Puppeteer: "${text}" in ${selector}`;
      } else {
        await page.keyboard.type(text);
        return `Text typed successfully using Puppeteer: "${text}"`;
      }
    }
  } catch (error) {
    throw new Error(`Failed to type text: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function takeScreenshot(browser: string): Promise<string> {
  try {
    const timestamp = Date.now();
    const screenshotPath = `./screenshot_${timestamp}.png`;
    
    const instances = Array.from(browserInstances.entries());
    if (instances.length === 0) {
      throw new Error('No browser instance available');
    }
    
    const [instanceId, instance] = instances[instances.length - 1];
    
    if (instance.type === 'playwright') {
      const page = instance.page as Page;
      await page.screenshot({ path: screenshotPath, fullPage: true });
      return screenshotPath;
    } else {
      const page = instance.page as PuppeteerPage;
      await page.screenshot({ path: screenshotPath, fullPage: true });
      return screenshotPath;
    }
  } catch (error) {
    throw new Error(`Failed to take screenshot: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function executeScript(browser: string, script: string): Promise<string> {
  try {
    const instances = Array.from(browserInstances.entries());
    if (instances.length === 0) {
      throw new Error('No browser instance available');
    }
    
    const [instanceId, instance] = instances[instances.length - 1];
    
    if (instance.type === 'playwright') {
      const page = instance.page as Page;
      const result = await page.evaluate(script);
      return `Script executed successfully using Playwright. Result: ${JSON.stringify(result)}`;
    } else {
      const page = instance.page as PuppeteerPage;
      const result = await page.evaluate(script);
      return `Script executed successfully using Puppeteer. Result: ${JSON.stringify(result)}`;
    }
  } catch (error) {
    throw new Error(`Failed to execute script: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function closeBrowser(browser: string): Promise<string> {
  try {
    const instances = Array.from(browserInstances.entries());
    if (instances.length === 0) {
      return 'No browser instances to close';
    }
    
    // Close all browser instances
    for (const [instanceId, instance] of instances) {
      if (instance.type === 'playwright') {
        const playwrightBrowser = instance.browser as Browser;
        await playwrightBrowser.close();
      } else {
        const puppeteerBrowser = instance.browser as PuppeteerBrowser;
        await puppeteerBrowser.close();
      }
      browserInstances.delete(instanceId);
    }
    
    return `${browser} browser instances closed successfully`;
  } catch (error) {
    return `${browser} browser close attempted (may not have been running): ${error instanceof Error ? error.message : 'Unknown error'}`;
  }
}

// System browser launch function
async function launchSystemBrowser(browser: string): Promise<string> {
  try {
    let command = "";
    
    switch (browser.toLowerCase()) {
      case "chrome":
      case "chromium":
        if (IS_WINDOWS) {
          command = `"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"`;
        } else if (IS_LINUX) {
          command = "google-chrome";
        } else if (IS_MACOS) {
          command = "open -a 'Google Chrome'";
        }
        break;
      case "firefox":
        if (IS_WINDOWS) {
          command = `"C:\\Program Files\\Mozilla Firefox\\firefox.exe"`;
        } else if (IS_LINUX) {
          command = "firefox";
        } else if (IS_MACOS) {
          command = "open -a 'Firefox'";
        }
        break;
      case "edge":
        if (IS_WINDOWS) {
          command = `"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"`;
        } else if (IS_LINUX) {
          command = "microsoft-edge";
        } else if (IS_MACOS) {
          command = "open -a 'Microsoft Edge'";
        }
        break;
      case "safari":
        if (IS_MACOS) {
          command = "open -a 'Safari'";
        } else {
          throw new Error("Safari is only available on macOS");
        }
        break;
      case "opera":
      case "operagx":
        if (IS_WINDOWS) {
          // Try OperaGX first, then regular Opera
          command = `"C:\\Users\\${process.env.USERNAME}\\AppData\\Local\\Programs\\Opera GX\\121.0.5600.81\\opera.exe"`;
        } else if (IS_LINUX) {
          command = "opera";
        } else if (IS_MACOS) {
          command = "open -a 'Opera'";
        }
        break;
      default:
        // Try system default
        if (IS_WINDOWS) {
          command = "start";
        } else if (IS_LINUX) {
          command = "xdg-open";
        } else if (IS_MACOS) {
          command = "open";
        }
    }
    
    if (!command) {
      throw new Error(`Unsupported browser: ${browser}`);
    }
    
    // Launch system browser (this will open a new browser window)
    const child = spawn(command, [], {
      stdio: 'pipe',
      detached: true
    });
    
    // Don't wait for the process to finish
    child.unref();
    
    return `${browser} system browser launched successfully`;
    
  } catch (error) {
    throw new Error(`Failed to launch system browser ${browser}: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

// Helper function to get browser instance
function getLatestBrowserInstance(): { browser: Browser | PuppeteerBrowser, context?: BrowserContext, page?: Page | PuppeteerPage, type: 'playwright' | 'puppeteer' } | null {
  const instances = Array.from(browserInstances.entries());
  if (instances.length === 0) return null;
  return instances[instances.length - 1][1];
}




