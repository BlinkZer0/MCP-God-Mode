#!/usr/bin/env node
import { z } from "zod";
import { exec } from "node:child_process";
import { promisify } from "node:util";
const execAsync = promisify(exec);
// Browser engines and their detection
const BROWSER_ENGINES = {
    playwright: {
        name: "Playwright",
        command: "npx playwright --version",
        install: "npm install playwright && npx playwright install"
    },
    puppeteer: {
        name: "Puppeteer",
        command: "npx puppeteer --version",
        install: "npm install puppeteer"
    },
    chrome: {
        name: "Chrome DevTools Protocol",
        command: "google-chrome --version || chromium --version || chrome --version",
        install: "Install Chrome or Chromium browser"
    }
};
export function registerUniversalBrowserOperator(server) {
    // Universal Browser Control Tool
    server.registerTool("universal_browser_operator", {
        description: "Universal browser automation and control tool with cross-platform support for web interaction, navigation, and automation tasks",
        inputSchema: {
            action: z.enum(["navigate", "click", "type", "screenshot", "get_text", "get_html", "evaluate", "wait", "scroll"]).describe("Browser action to perform"),
            url: z.string().optional().describe("URL to navigate to (for navigate action)"),
            selector: z.string().optional().describe("CSS selector for element interaction"),
            text: z.string().optional().describe("Text to type (for type action)"),
            script: z.string().optional().describe("JavaScript to evaluate (for evaluate action)"),
            timeout: z.number().min(1000).max(120000).default(30000).describe("Timeout in milliseconds"),
            headless: z.boolean().default(false).describe("Run browser in headless mode")
        },
        outputSchema: {
            success: z.boolean(),
            result: z.string().optional(),
            screenshot_path: z.string().optional(),
            error: z.string().optional(),
            action: z.string(),
            url: z.string().optional()
        }
    }, async ({ action, url, selector, text, script, timeout, headless }) => {
        try {
            const result = await performBrowserAction(action, url, selector, text, script, timeout, headless);
            return {
                content: [{ type: "text", text: `Browser action '${action}' completed successfully` }],
                structuredContent: {
                    success: true,
                    result: result.result,
                    screenshot_path: result.screenshot,
                    action,
                    url: result.url
                }
            };
        }
        catch (error) {
            return {
                content: [{ type: "text", text: `Browser action failed: ${error instanceof Error ? error.message : 'Unknown error'}` }],
                structuredContent: {
                    success: false,
                    error: `Browser action failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
                    action,
                    url
                }
            };
        }
    });
}
// Helper functions
async function detectBrowserEngine() {
    const engines = [
        { name: 'playwright', command: 'npx playwright --version' },
        { name: 'puppeteer', command: 'npx puppeteer --version' },
        { name: 'chrome', command: 'google-chrome --version || chromium --version || chrome --version' }
    ];
    for (const engine of engines) {
        try {
            await execAsync(engine.command);
            return engine.name;
        }
        catch (error) {
            continue;
        }
    }
    throw new Error("No browser engine available. Please install Playwright, Puppeteer, or Chrome.");
}
async function launchBrowser(engine, headless = true) {
    switch (engine) {
        case 'playwright':
            const { chromium } = await import('playwright');
            return await chromium.launch({
                headless,
                args: ['--no-sandbox', '--disable-setuid-sandbox']
            });
        case 'puppeteer':
            const puppeteer = await import('puppeteer');
            return await puppeteer.launch({
                headless,
                args: ['--no-sandbox', '--disable-setuid-sandbox']
            });
        case 'chrome':
            const { chromium: chrome } = await import('playwright');
            return await chrome.launch({
                headless,
                args: ['--no-sandbox', '--disable-setuid-sandbox']
            });
        default:
            throw new Error(`Unsupported browser engine: ${engine}`);
    }
}
async function performBrowserAction(action, url, selector, text, script, timeout = 30000, headless = false) {
    const engine = await detectBrowserEngine();
    const browser = await launchBrowser(engine, headless);
    try {
        const page = await browser.newPage();
        let result = '';
        let screenshotPath = '';
        switch (action) {
            case 'navigate':
                if (!url)
                    throw new Error('URL is required for navigate action');
                await page.goto(url, { waitUntil: 'domcontentloaded', timeout });
                result = `Navigated to ${url}`;
                break;
            case 'click':
                if (!selector)
                    throw new Error('Selector is required for click action');
                await page.waitForSelector(selector, { timeout });
                await page.click(selector);
                result = `Clicked element: ${selector}`;
                break;
            case 'type':
                if (!selector || !text)
                    throw new Error('Selector and text are required for type action');
                await page.waitForSelector(selector, { timeout });
                await page.fill(selector, text);
                result = `Typed text into element: ${selector}`;
                break;
            case 'screenshot':
                screenshotPath = `./browser_screenshot_${Date.now()}.png`;
                await page.screenshot({ path: screenshotPath, fullPage: true });
                result = `Screenshot saved to: ${screenshotPath}`;
                break;
            case 'get_text':
                if (!selector)
                    throw new Error('Selector is required for get_text action');
                await page.waitForSelector(selector, { timeout });
                result = await page.textContent(selector);
                break;
            case 'get_html':
                if (!selector)
                    throw new Error('Selector is required for get_html action');
                await page.waitForSelector(selector, { timeout });
                result = await page.innerHTML(selector);
                break;
            case 'evaluate':
                if (!script)
                    throw new Error('Script is required for evaluate action');
                result = await page.evaluate(script);
                break;
            case 'wait':
                if (selector) {
                    await page.waitForSelector(selector, { timeout });
                    result = `Waited for element: ${selector}`;
                }
                else {
                    await new Promise(resolve => setTimeout(resolve, timeout));
                    result = `Waited for ${timeout}ms`;
                }
                break;
            case 'scroll':
                await page.evaluate(() => {
                    window.scrollTo(0, document.body.scrollHeight);
                });
                result = 'Scrolled to bottom of page';
                break;
            default:
                throw new Error(`Unknown action: ${action}`);
        }
        return {
            content: [{ type: "text", text: "Operation completed successfully" }],
            result,
            screenshot: screenshotPath,
            url: page.url()
        };
    }
    finally {
        await browser.close();
    }
}
