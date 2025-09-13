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
      console.log(`Playwright failed, trying Puppeteer fallback: ${playwrightError}`);
      
      // Fallback to Puppeteer
      let puppeteerBrowser: PuppeteerBrowser;
      let puppeteerPage: PuppeteerPage;
      
      puppeteerBrowser = await puppeteer.launch({
        headless,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });
      
      puppeteerPage = await puppeteerBrowser.newPage();
      
      browserInstances.set(instanceId, {
        browser: puppeteerBrowser,
        page: puppeteerPage,
        type: 'puppeteer'
      });
      
      return `${browser} browser launched successfully with Puppeteer fallback${headless ? ' (headless mode)' : ''}`;
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
  } catch (error) {
    throw new Error(`Failed to navigate to ${url}: ${error instanceof Error ? error.message : 'Unknown error'}`);
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

// Helper function to get browser instance
function getLatestBrowserInstance(): { browser: Browser | PuppeteerBrowser, context?: BrowserContext, page?: Page | PuppeteerPage, type: 'playwright' | 'puppeteer' } | null {
  const instances = Array.from(browserInstances.entries());
  if (instances.length === 0) return null;
  return instances[instances.length - 1][1];
}




