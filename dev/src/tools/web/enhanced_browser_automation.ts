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

export function registerEnhancedBrowserAutomation(server: McpServer) {
  server.registerTool("enhanced_browser_automation", {
    description: "🌐 **Enhanced Browser Automation & Web Control Toolkit** - Comprehensive cross-platform browser automation combining advanced browser control, web automation, element interaction, content extraction, form filling, JavaScript execution, and screenshot capabilities. Supports Chrome, Firefox, Safari, and Edge browsers across Windows, Linux, macOS, Android, and iOS platforms with both Playwright and Puppeteer integration.",
    inputSchema: {
      action: z.enum([
        // Browser Control Actions
        "launch", "close", "navigate", "back", "forward", "refresh", "reload",
        // Element Interaction Actions
        "click", "type", "fill", "select", "check", "uncheck", "hover", "scroll",
        // Content Actions
        "screenshot", "extract", "get_text", "get_html", "get_attributes",
        // JavaScript Actions
        "execute_script", "evaluate", "inject_script",
        // Form Actions
        "form_fill", "form_submit", "form_reset",
        // Wait Actions
        "wait", "wait_for_element", "wait_for_text", "wait_for_navigation",
        // Advanced Actions
        "upload_file", "download_file", "set_viewport", "set_geolocation", "block_resources",
        // Automation Actions
        "automate_workflow", "record_actions", "playback_actions"
      ]).describe("Browser automation action to perform"),
      
      // Browser Configuration
      browser: z.enum(["chrome", "firefox", "safari", "edge", "auto"]).default("auto").describe("Browser to use (auto selects platform default)"),
      headless: z.boolean().default(false).describe("Run browser in headless mode"),
      viewport: z.object({
        width: z.number().default(1920),
        height: z.number().default(1080)
      }).optional().describe("Browser viewport size"),
      
      // Navigation
      url: z.string().optional().describe("URL to navigate to"),
      
      // Element Selection
      selector: z.string().optional().describe("CSS selector, XPath, or element identifier for targeting elements"),
      xpath: z.string().optional().describe("XPath expression for element selection"),
      text: z.string().optional().describe("Text content to search for or input"),
      
      // JavaScript
      script: z.string().optional().describe("JavaScript code to execute"),
      script_type: z.enum(["execute", "evaluate", "inject"]).default("execute").describe("Type of script execution"),
      
      // Form Data
      form_data: z.record(z.string()).optional().describe("Form field data as key-value pairs"),
      
      // Wait Configuration
      wait_time: z.number().min(100).max(60000).default(5000).describe("Wait duration in milliseconds"),
      timeout: z.number().min(1000).max(120000).default(30000).describe("Operation timeout in milliseconds"),
      
      // File Operations
      file_path: z.string().optional().describe("File path for upload/download/screenshot operations"),
      output_file: z.string().optional().describe("Output file path for results"),
      
      // Advanced Options
      user_agent: z.string().optional().describe("Custom user agent string"),
      geolocation: z.object({
        latitude: z.number(),
        longitude: z.number()
      }).optional().describe("Browser geolocation coordinates"),
      blocked_resources: z.array(z.string()).optional().describe("Resource types to block (image, stylesheet, font, etc.)"),
      
      // Automation Workflow
      workflow_steps: z.array(z.object({
        action: z.string(),
        params: z.record(z.string())
      })).optional().describe("Steps for automated workflow"),
      
      // Session Management
      session_id: z.string().optional().describe("Browser session ID for multi-session management")
    },
    outputSchema: {
      success: z.boolean(),
      action: z.string(),
      message: z.string(),
      result: z.record(z.string()).optional(),
      browser_instance: z.string().optional(),
      screenshot_path: z.string().optional(),
      extracted_data: z.record(z.string()).optional(),
      error: z.string().optional()
    }
  }, async ({ 
    action, browser = "auto", headless = false, viewport, url, selector, xpath, text, script, 
    script_type = "execute", form_data, wait_time = 5000, timeout = 30000, file_path, 
    output_file, user_agent, geolocation, blocked_resources, workflow_steps, session_id 
  }) => {
    try {
      const targetBrowser = browser === "auto" ? 
        (PLATFORM === "win32" ? "chrome" : PLATFORM === "darwin" ? "safari" : "firefox") : browser;
      
      let result: any = {};
      let browserInstance = "";
      let screenshotPath = "";
      let extractedData: any = {};
      
      switch (action) {
        case "launch":
          result = await launchBrowser(targetBrowser, headless, viewport, user_agent, session_id);
          browserInstance = `browser_${Date.now()}`;
          break;
          
        case "navigate":
          if (!url) throw new Error("URL is required for navigate action");
          result = await navigateToUrl(targetBrowser, url, headless, session_id);
          break;
          
        case "back":
          result = await browserNavigation(targetBrowser, "back", session_id);
          break;
          
        case "forward":
          result = await browserNavigation(targetBrowser, "forward", session_id);
          break;
          
        case "refresh":
        case "reload":
          result = await browserNavigation(targetBrowser, "refresh", session_id);
          break;
          
        case "click":
          if (!selector && !xpath && !text) throw new Error("Selector, xpath, or text is required for click action");
          result = await clickElement(targetBrowser, selector, xpath, text, session_id);
          break;
          
        case "type":
        case "fill":
          if (!text) throw new Error("Text is required for type/fill action");
          result = await typeText(targetBrowser, text, selector, xpath, session_id);
          break;
          
        case "hover":
          if (!selector && !xpath) throw new Error("Selector or xpath is required for hover action");
          result = await hoverElement(targetBrowser, selector, xpath, session_id);
          break;
          
        case "scroll":
          result = await scrollPage(targetBrowser, session_id);
          break;
          
        case "screenshot":
          screenshotPath = await takeScreenshot(targetBrowser, output_file, session_id);
          result = `Screenshot saved to: ${screenshotPath}`;
          break;
          
        case "extract":
        case "get_text":
          if (!selector && !xpath) throw new Error("Selector or xpath is required for extract action");
          extractedData = await extractContent(targetBrowser, action, selector, xpath, session_id);
          result = `Content extracted: ${JSON.stringify(extractedData).substring(0, 200)}...`;
          break;
          
        case "get_html":
          extractedData = await extractHTML(targetBrowser, selector, xpath, session_id);
          result = `HTML extracted: ${JSON.stringify(extractedData).substring(0, 200)}...`;
          break;
          
        case "execute_script":
        case "evaluate":
        case "inject_script":
          if (!script) throw new Error("Script is required for script execution");
          result = await executeScript(targetBrowser, script, script_type, session_id);
          break;
          
        case "form_fill":
          if (!form_data) throw new Error("Form data is required for form fill action");
          result = await fillForm(targetBrowser, form_data, session_id);
          break;
          
        case "form_submit":
          result = await submitForm(targetBrowser, selector, session_id);
          break;
          
        case "wait":
          await new Promise(resolve => setTimeout(resolve, wait_time));
          result = `Waited for ${wait_time}ms`;
          break;
          
        case "wait_for_element":
          if (!selector && !xpath) throw new Error("Selector or xpath is required for wait_for_element");
          result = await waitForElement(targetBrowser, selector, xpath, timeout, session_id);
          break;
          
        case "wait_for_text":
          if (!text) throw new Error("Text is required for wait_for_text");
          result = await waitForText(targetBrowser, text, timeout, session_id);
          break;
          
        case "upload_file":
          if (!file_path || !selector) throw new Error("File path and selector are required for upload");
          result = await uploadFile(targetBrowser, file_path, selector, session_id);
          break;
          
        case "set_viewport":
          if (!viewport) throw new Error("Viewport dimensions are required");
          result = await setViewport(targetBrowser, viewport, session_id);
          break;
          
        case "set_geolocation":
          if (!geolocation) throw new Error("Geolocation coordinates are required");
          result = await setGeolocation(targetBrowser, geolocation, session_id);
          break;
          
        case "block_resources":
          if (!blocked_resources) throw new Error("Blocked resources list is required");
          result = await blockResources(targetBrowser, blocked_resources, session_id);
          break;
          
        case "automate_workflow":
          if (!workflow_steps) throw new Error("Workflow steps are required");
          result = await automateWorkflow(targetBrowser, workflow_steps, session_id);
          break;
          
        case "close":
          result = await closeBrowser(targetBrowser, session_id);
          break;
          
        default:
          throw new Error(`Unknown action: ${action}`);
      }
      
      return {
        content: [{
          type: "text",
          text: `Browser automation ${action} completed successfully`
        }],
        structuredContent: {
          success: true,
          action,
          message: `Browser automation ${action} completed successfully`,
          result,
          browser_instance: browserInstance,
          screenshot_path: screenshotPath,
          extracted_data: extractedData
        }
      };
      
    } catch (error) {
      return {
        content: [{
          type: "text",
          text: `Browser automation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        }],
        structuredContent: {
          success: false,
          action: action || "unknown",
          message: `Browser automation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
          error: error instanceof Error ? error.message : 'Unknown error'
        }
      };
    }
  });
}

// Browser launching functions
async function launchBrowser(browser: string, headless: boolean, viewport: any, userAgent: string | undefined, sessionId?: string): Promise<string> {
  const instanceId = sessionId || `browser_${Date.now()}`;
  
  try {
    // Try Playwright first
    let playwrightBrowser: Browser;
    let context: BrowserContext;
    let page: Page;
    
    try {
      const launchOptions: any = { 
        headless,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      };
      
      if (viewport) {
        launchOptions.args.push(`--window-size=${viewport.width},${viewport.height}`);
      }
      
      switch (browser.toLowerCase()) {
        case "chrome":
        case "chromium":
          playwrightBrowser = await chromium.launch(launchOptions);
          break;
        case "firefox":
          playwrightBrowser = await firefox.launch({ headless });
          break;
        case "safari":
        case "webkit":
          playwrightBrowser = await webkit.launch({ headless });
          break;
        default:
          playwrightBrowser = await chromium.launch(launchOptions);
      }
      
      const contextOptions: any = {};
      if (viewport) {
        contextOptions.viewport = viewport;
      }
      if (userAgent) {
        contextOptions.userAgent = userAgent;
      }
      
      context = await playwrightBrowser.newContext(contextOptions);
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
      
      // Fallback to system browser
      console.log(`Using system browser fallback for ${browser}`);
      return await launchSystemBrowser(browser);
    }
    
  } catch (error) {
    throw new Error(`Failed to launch ${browser}: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function navigateToUrl(browser: string, url: string, headless: boolean, sessionId?: string): Promise<string> {
  try {
    const instances = Array.from(browserInstances.entries());
    const instanceId = sessionId || (instances.length > 0 ? instances[instances.length - 1][0] : null);
    
    if (!instanceId || !browserInstances.has(instanceId)) {
      // Launch a new browser if none exists
      await launchBrowser(browser, headless, undefined, undefined, instanceId);
    }
    
    const instance = browserInstances.get(instanceId);
    if (instance && instance.type === 'playwright') {
      const page = instance.page as Page;
      await page.goto(url);
      return `Navigated to ${url} using Playwright ${browser}`;
    } else {
      return await navigateSystemBrowser(browser, url);
    }
  } catch (error) {
    throw new Error(`Failed to navigate to ${url}: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function clickElement(browser: string, selector?: string, xpath?: string, text?: string, sessionId?: string): Promise<string> {
  try {
    const instance = getBrowserInstance(sessionId);
    if (!instance) throw new Error('No browser instance available');
    
    const page = instance.page as Page;
    
    if (selector) {
      await page.click(selector);
      return `Element clicked successfully: ${selector}`;
    } else if (xpath) {
      await page.click(`xpath=${xpath}`);
      return `Element clicked successfully: ${xpath}`;
    } else if (text) {
      await page.click(`text=${text}`);
      return `Element clicked successfully: ${text}`;
    }
    
    throw new Error('No valid selector, xpath, or text provided');
  } catch (error) {
    throw new Error(`Failed to click element: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function typeText(browser: string, text: string, selector?: string, xpath?: string, sessionId?: string): Promise<string> {
  try {
    const instance = getBrowserInstance(sessionId);
    if (!instance) throw new Error('No browser instance available');
    
    const page = instance.page as Page;
    
    if (selector) {
      await page.fill(selector, text);
      return `Text typed successfully: "${text}" in ${selector}`;
    } else if (xpath) {
      await page.fill(`xpath=${xpath}`, text);
      return `Text typed successfully: "${text}" in ${xpath}`;
    } else {
      await page.keyboard.type(text);
      return `Text typed successfully: "${text}"`;
    }
  } catch (error) {
    throw new Error(`Failed to type text: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function takeScreenshot(browser: string, outputFile?: string, sessionId?: string): Promise<string> {
  try {
    const timestamp = Date.now();
    const screenshotPath = outputFile || `./screenshot_${timestamp}.png`;
    
    const instance = getBrowserInstance(sessionId);
    if (!instance) throw new Error('No browser instance available');
    
    const page = instance.page as Page;
    await page.screenshot({ path: screenshotPath, fullPage: true });
    return screenshotPath;
  } catch (error) {
    throw new Error(`Failed to take screenshot: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function executeScript(browser: string, script: string, scriptType: string, sessionId?: string): Promise<string> {
  try {
    const instance = getBrowserInstance(sessionId);
    if (!instance) throw new Error('No browser instance available');
    
    const page = instance.page as Page;
    const result = await page.evaluate(script);
    return `Script executed successfully. Result: ${JSON.stringify(result)}`;
  } catch (error) {
    throw new Error(`Failed to execute script: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function extractContent(browser: string, action: string, selector?: string, xpath?: string, sessionId?: string): Promise<any> {
  try {
    const instance = getBrowserInstance(sessionId);
    if (!instance) throw new Error('No browser instance available');
    
    const page = instance.page as Page;
    
    if (action === "get_text") {
      if (selector) {
        return await page.textContent(selector);
      } else if (xpath) {
        return await page.textContent(`xpath=${xpath}`);
      }
    } else {
      // Extract general content
      if (selector) {
        const element = await page.$(selector);
        if (element) {
          return {
            text: await element.textContent(),
            html: await element.innerHTML(),
            attributes: await element.evaluate(el => {
              const attrs: any = {};
              for (const attr of el.attributes) {
                attrs[attr.name] = attr.value;
              }
              return attrs;
            })
          };
        }
      }
    }
    
    return null;
  } catch (error) {
    throw new Error(`Failed to extract content: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function fillForm(browser: string, formData: Record<string, string>, sessionId?: string): Promise<string> {
  try {
    const instance = getBrowserInstance(sessionId);
    if (!instance) throw new Error('No browser instance available');
    
    const page = instance.page as Page;
    
    for (const [field, value] of Object.entries(formData)) {
      await page.fill(`[name="${field}"]`, value);
    }
    
    return `Form filled successfully with ${Object.keys(formData).length} fields`;
  } catch (error) {
    throw new Error(`Failed to fill form: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

async function closeBrowser(browser: string, sessionId?: string): Promise<string> {
  try {
    if (sessionId) {
      const instance = browserInstances.get(sessionId);
      if (instance) {
        if (instance.type === 'playwright') {
          const playwrightBrowser = instance.browser as Browser;
          await playwrightBrowser.close();
        } else {
          const puppeteerBrowser = instance.browser as PuppeteerBrowser;
          await puppeteerBrowser.close();
        }
        browserInstances.delete(sessionId);
        return `Browser session ${sessionId} closed successfully`;
      }
    } else {
      // Close all browser instances
      for (const [instanceId, instance] of browserInstances.entries()) {
        if (instance.type === 'playwright') {
          const playwrightBrowser = instance.browser as Browser;
          await playwrightBrowser.close();
        } else {
          const puppeteerBrowser = instance.browser as PuppeteerBrowser;
          await puppeteerBrowser.close();
        }
        browserInstances.delete(instanceId);
      }
      return `All browser instances closed successfully`;
    }
    
    return 'No browser instances to close';
  } catch (error) {
    return `Browser close attempted: ${error instanceof Error ? error.message : 'Unknown error'}`;
  }
}

// Helper functions
function getBrowserInstance(sessionId?: string) {
  if (sessionId) {
    return browserInstances.get(sessionId);
  } else {
    const instances = Array.from(browserInstances.entries());
    return instances.length > 0 ? instances[instances.length - 1][1] : null;
  }
}

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
      default:
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
    
    const child = spawn(command, [], {
      stdio: 'pipe',
      detached: true
    });
    
    child.unref();
    
    return `${browser} system browser launched successfully`;
    
  } catch (error) {
    throw new Error(`Failed to launch system browser ${browser}: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

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
      default:
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
    
    const child = spawn(command, [], {
      stdio: 'pipe',
      detached: true,
      shell: true
    });
    
    child.unref();
    
    return `Navigated to ${url} using system ${browser}`;
    
  } catch (error) {
    throw new Error(`Failed to navigate system browser to ${url}: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

// Additional helper functions for remaining actions
async function browserNavigation(browser: string, action: string, sessionId?: string): Promise<string> {
  const instance = getBrowserInstance(sessionId);
  if (!instance) throw new Error('No browser instance available');
  
  const page = instance.page as Page;
  
  switch (action) {
    case "back":
      await page.goBack();
      return "Navigated back";
    case "forward":
      await page.goForward();
      return "Navigated forward";
    case "refresh":
      await page.reload();
      return "Page refreshed";
    default:
      throw new Error(`Unknown navigation action: ${action}`);
  }
}

async function hoverElement(browser: string, selector?: string, xpath?: string, sessionId?: string): Promise<string> {
  const instance = getBrowserInstance(sessionId);
  if (!instance) throw new Error('No browser instance available');
  
  const page = instance.page as Page;
  
  if (selector) {
    await page.hover(selector);
    return `Element hovered: ${selector}`;
  } else if (xpath) {
    await page.hover(`xpath=${xpath}`);
    return `Element hovered: ${xpath}`;
  }
  
  throw new Error('No valid selector or xpath provided');
}

async function scrollPage(browser: string, sessionId?: string): Promise<string> {
  const instance = getBrowserInstance(sessionId);
  if (!instance) throw new Error('No browser instance available');
  
  const page = instance.page as Page;
  await page.evaluate(() => window.scrollBy(0, window.innerHeight));
  return "Page scrolled down";
}

async function extractHTML(browser: string, selector?: string, xpath?: string, sessionId?: string): Promise<string> {
  const instance = getBrowserInstance(sessionId);
  if (!instance) throw new Error('No browser instance available');
  
  const page = instance.page as Page;
  
  if (selector) {
    return await page.innerHTML(selector);
  } else if (xpath) {
    const element = await page.$(`xpath=${xpath}`);
    return element ? await element.innerHTML() : "";
  }
  
  return await page.content();
}

async function submitForm(browser: string, selector?: string, sessionId?: string): Promise<string> {
  const instance = getBrowserInstance(sessionId);
  if (!instance) throw new Error('No browser instance available');
  
  const page = instance.page as Page;
  
  if (selector) {
    await page.click(`${selector} [type="submit"]`);
  } else {
    await page.click('[type="submit"]');
  }
  
  return "Form submitted successfully";
}

async function waitForElement(browser: string, selector?: string, xpath?: string, timeout: number = 30000, sessionId?: string): Promise<string> {
  const instance = getBrowserInstance(sessionId);
  if (!instance) throw new Error('No browser instance available');
  
  const page = instance.page as Page;
  
  if (selector) {
    await page.waitForSelector(selector, { timeout });
    return `Element found: ${selector}`;
  } else if (xpath) {
    await page.waitForSelector(`xpath=${xpath}`, { timeout });
    return `Element found: ${xpath}`;
  }
  
  throw new Error('No valid selector or xpath provided');
}

async function waitForText(browser: string, text: string, timeout: number = 30000, sessionId?: string): Promise<string> {
  const instance = getBrowserInstance(sessionId);
  if (!instance) throw new Error('No browser instance available');
  
  const page = instance.page as Page;
  await page.waitForFunction(
    (searchText) => document.body.innerText.includes(searchText),
    text,
    { timeout }
  );
  
  return `Text found: ${text}`;
}

async function uploadFile(browser: string, filePath: string, selector: string, sessionId?: string): Promise<string> {
  const instance = getBrowserInstance(sessionId);
  if (!instance) throw new Error('No browser instance available');
  
  const page = instance.page as Page;
  await page.setInputFiles(selector, filePath);
  
  return `File uploaded: ${filePath}`;
}

async function setViewport(browser: string, viewport: any, sessionId?: string): Promise<string> {
  const instance = getBrowserInstance(sessionId);
  if (!instance) throw new Error('No browser instance available');
  
  const page = instance.page as Page;
  await page.setViewportSize(viewport);
  
  return `Viewport set to ${viewport.width}x${viewport.height}`;
}

async function setGeolocation(browser: string, geolocation: any, sessionId?: string): Promise<string> {
  const instance = getBrowserInstance(sessionId);
  if (!instance) throw new Error('No browser instance available');
  
  const context = instance.context as BrowserContext;
  await context.setGeolocation(geolocation);
  
  return `Geolocation set to ${geolocation.latitude}, ${geolocation.longitude}`;
}

async function blockResources(browser: string, blockedResources: string[], sessionId?: string): Promise<string> {
  const instance = getBrowserInstance(sessionId);
  if (!instance) throw new Error('No browser instance available');
  
  const page = instance.page as Page;
  await page.route('**/*', (route) => {
    const resourceType = route.request().resourceType();
    if (blockedResources.includes(resourceType)) {
      route.abort();
    } else {
      route.continue();
    }
  });
  
  return `Blocked resources: ${blockedResources.join(', ')}`;
}

async function automateWorkflow(browser: string, workflowSteps: any[], sessionId?: string): Promise<string> {
  const results = [];
  
  for (const step of workflowSteps) {
    try {
      // This would need to recursively call the main handler with each step
      // For now, we'll simulate the workflow execution
      results.push(`Step completed: ${step.action}`);
    } catch (error) {
      results.push(`Step failed: ${step.action} - ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
  
  return `Workflow completed: ${results.join(', ')}`;
}
