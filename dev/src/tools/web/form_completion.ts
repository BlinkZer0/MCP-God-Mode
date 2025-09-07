#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { spawn, exec } from "node:child_process";
import { promisify } from "node:util";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";

const execAsync = promisify(exec);

// Form field types and their detection patterns
const FORM_FIELD_TYPES = {
  text: {
    selectors: ['input[type="text"]', 'input:not([type])', 'textarea'],
    patterns: ['name', 'email', 'username', 'firstname', 'lastname', 'address', 'city', 'state', 'zip', 'phone', 'company', 'title']
  },
  email: {
    selectors: ['input[type="email"]', 'input[name*="email"]', 'input[id*="email"]'],
    patterns: ['email', 'e-mail', 'mail']
  },
  password: {
    selectors: ['input[type="password"]', 'input[name*="password"]', 'input[id*="password"]'],
    patterns: ['password', 'pass', 'pwd', 'secret']
  },
  number: {
    selectors: ['input[type="number"]', 'input[name*="number"]', 'input[id*="number"]'],
    patterns: ['number', 'phone', 'zip', 'age', 'quantity', 'amount']
  },
  date: {
    selectors: ['input[type="date"]', 'input[name*="date"]', 'input[id*="date"]'],
    patterns: ['date', 'birth', 'dob', 'expiry', 'expire']
  },
  checkbox: {
    selectors: ['input[type="checkbox"]'],
    patterns: ['agree', 'accept', 'terms', 'newsletter', 'subscribe']
  },
  radio: {
    selectors: ['input[type="radio"]'],
    patterns: ['gender', 'sex', 'type', 'category', 'option']
  },
  select: {
    selectors: ['select', 'datalist'],
    patterns: ['country', 'state', 'province', 'city', 'category', 'type', 'option']
  },
  file: {
    selectors: ['input[type="file"]'],
    patterns: ['file', 'upload', 'document', 'image', 'photo', 'attachment']
  },
  hidden: {
    selectors: ['input[type="hidden"]'],
    patterns: ['token', 'csrf', 'session', 'id', 'key']
  }
};

// Common form patterns and their field mappings
const FORM_PATTERNS = {
  contact: {
    name: 'contact_form',
    fields: {
      'name': { type: 'text', required: true, patterns: ['name', 'fullname', 'full_name'] },
      'email': { type: 'email', required: true, patterns: ['email', 'e-mail'] },
      'phone': { type: 'text', required: false, patterns: ['phone', 'telephone', 'mobile'] },
      'message': { type: 'textarea', required: true, patterns: ['message', 'comment', 'inquiry'] },
      'subject': { type: 'text', required: false, patterns: ['subject', 'topic'] }
    }
  },
  registration: {
    name: 'registration_form',
    fields: {
      'username': { type: 'text', required: true, patterns: ['username', 'user', 'login'] },
      'email': { type: 'email', required: true, patterns: ['email', 'e-mail'] },
      'password': { type: 'password', required: true, patterns: ['password', 'pass'] },
      'confirm_password': { type: 'password', required: true, patterns: ['confirm', 'verify', 'repeat'] },
      'first_name': { type: 'text', required: true, patterns: ['firstname', 'first_name', 'fname'] },
      'last_name': { type: 'text', required: true, patterns: ['lastname', 'last_name', 'lname'] }
    }
  },
  login: {
    name: 'login_form',
    fields: {
      'username': { type: 'text', required: true, patterns: ['username', 'user', 'email', 'login'] },
      'password': { type: 'password', required: true, patterns: ['password', 'pass'] }
    }
  },
  checkout: {
    name: 'checkout_form',
    fields: {
      'first_name': { type: 'text', required: true, patterns: ['firstname', 'first_name', 'fname'] },
      'last_name': { type: 'text', required: true, patterns: ['lastname', 'last_name', 'lname'] },
      'email': { type: 'email', required: true, patterns: ['email', 'e-mail'] },
      'phone': { type: 'text', required: true, patterns: ['phone', 'telephone', 'mobile'] },
      'address': { type: 'text', required: true, patterns: ['address', 'street', 'addr'] },
      'city': { type: 'text', required: true, patterns: ['city', 'town'] },
      'state': { type: 'text', required: true, patterns: ['state', 'province', 'region'] },
      'zip': { type: 'text', required: true, patterns: ['zip', 'postal', 'postcode'] },
      'country': { type: 'select', required: true, patterns: ['country', 'nation'] }
    }
  },
  newsletter: {
    name: 'newsletter_form',
    fields: {
      'email': { type: 'email', required: true, patterns: ['email', 'e-mail'] },
      'name': { type: 'text', required: false, patterns: ['name', 'fullname'] },
      'subscribe': { type: 'checkbox', required: false, patterns: ['subscribe', 'newsletter', 'agree'] }
    }
  }
};

// Validation rules for different field types
const VALIDATION_RULES = {
  email: {
    pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    message: 'Invalid email format'
  },
  phone: {
    pattern: /^[\+]?[1-9][\d]{0,15}$/,
    message: 'Invalid phone number format'
  },
  zip: {
    pattern: /^\d{5}(-\d{4})?$/,
    message: 'Invalid ZIP code format'
  },
  password: {
    minLength: 8,
    message: 'Password must be at least 8 characters'
  },
  required: {
    message: 'This field is required'
  }
};

export function registerFormCompletion(server: McpServer) {
  // Form Detection Tool
  server.registerTool("mcp_mcp-god-mode_form_detection", {
    description: "Detect and analyze forms on web pages, identifying field types, patterns, and completion requirements",
    inputSchema: {
      url: z.string().describe("URL of the page containing the form"),
      form_selector: z.string().optional().describe("CSS selector for specific form (if multiple forms exist)"),
      timeout: z.number().min(5000).max(60000).default(30000).describe("Timeout in milliseconds"),
      save_screenshot: z.boolean().default(true).describe("Save screenshot of the form")
    },
    outputSchema: {
      success: z.boolean(),
      forms: z.array(z.object({
        form_id: z.string().optional(),
        form_class: z.string().optional(),
        form_action: z.string().optional(),
        form_method: z.string().optional(),
        fields: z.array(z.object({
          name: z.string(),
          type: z.string(),
          required: z.boolean(),
          placeholder: z.string().optional(),
          value: z.string().optional(),
          options: z.array(z.string()).optional(),
          validation: z.string().optional()
        })),
        pattern: z.string().optional(),
        complexity: z.enum(["low", "medium", "high"])
      })),
      screenshot_path: z.string().optional(),
      error: z.string().optional(),
      page_title: z.string().optional()
    }
  }, async ({ url, form_selector, timeout, save_screenshot }) => {
    try {
      const result = await detectForms(url, form_selector, timeout, save_screenshot);

      return {
        content: [{ type: "text", text: `Form detection completed. Found ${result.forms.length} forms.` }],
        structuredContent: {
          success: true,
          forms: result.forms,
          screenshot_path: result.screenshot,
          page_title: result.title
        }
      };

    } catch (error) {
      return {
        content: [{ type: "text", text: `Form detection failed: ${error instanceof Error ? error.message : 'Unknown error'}` }],
        structuredContent: {
          success: false,
          error: `Form detection failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
          forms: []
        }
      };
    }
  });

  // Form Completion Tool
  server.registerTool("mcp_mcp-god-mode_form_completion", {
    description: "Complete online forms automatically with intelligent field detection, validation, and CAPTCHA handling",
    inputSchema: {
      url: z.string().describe("URL of the form to complete"),
      form_data: z.record(z.string()).describe("Form data to fill (field_name: value pairs)"),
      form_selector: z.string().optional().describe("CSS selector for specific form (if multiple forms exist)"),
      captcha_handling: z.enum(["auto", "solve", "skip", "manual"]).default("auto").describe("How to handle CAPTCHAs"),
      validation: z.boolean().default(true).describe("Validate form fields before submission"),
      submit_form: z.boolean().default(false).describe("Whether to submit the form after completion"),
      timeout: z.number().min(10000).max(300000).default(60000).describe("Timeout in milliseconds"),
      save_screenshot: z.boolean().default(true).describe("Save screenshot after completion")
    },
    outputSchema: {
      success: z.boolean(),
      fields_filled: z.number(),
      fields_detected: z.number(),
      captcha_solved: z.boolean().optional(),
      form_submitted: z.boolean().optional(),
      screenshot_path: z.string().optional(),
      error: z.string().optional(),
      validation_errors: z.array(z.string()).optional(),
      completion_summary: z.object({
        successful_fields: z.array(z.string()),
        failed_fields: z.array(z.string()),
        skipped_fields: z.array(z.string()),
        captcha_status: z.string().optional()
      }).optional()
    }
  }, async ({ url, form_data, form_selector, captcha_handling, validation, submit_form, timeout, save_screenshot }) => {
    try {
      const result = await completeForm(url, form_data, form_selector, captcha_handling, validation, submit_form, timeout, save_screenshot);

      return {
        content: [{ type: "text", text: `Form completion completed. Filled ${result.fieldsFilled} fields.` }],
        structuredContent: {
          success: true,
          fields_filled: result.fieldsFilled,
          fields_detected: result.fieldsDetected,
          captcha_solved: result.captchaSolved,
          form_submitted: result.formSubmitted,
          screenshot_path: result.screenshot,
          validation_errors: result.validationErrors,
          completion_summary: result.summary
        }
      };

    } catch (error) {
      return {
        content: [{ type: "text", text: `Form completion failed: ${error instanceof Error ? error.message : 'Unknown error'}` }],
        structuredContent: {
          success: false,
          error: `Form completion failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
          fields_filled: 0,
          fields_detected: 0
        }
      };
    }
  });

  // Form Validation Tool
  server.registerTool("mcp_mcp-god-mode_form_validation", {
    description: "Validate form data against field requirements, patterns, and business rules",
    inputSchema: {
      form_data: z.record(z.string()).describe("Form data to validate"),
      validation_rules: z.record(z.object({
        required: z.boolean().optional(),
        type: z.string().optional(),
        pattern: z.string().optional(),
        min_length: z.number().optional(),
        max_length: z.number().optional(),
        custom_validation: z.string().optional()
      })).optional().describe("Custom validation rules for specific fields"),
      strict_mode: z.boolean().default(false).describe("Use strict validation mode")
    },
    outputSchema: {
      success: z.boolean(),
      valid: z.boolean(),
      errors: z.array(z.object({
        field: z.string(),
        error: z.string(),
        value: z.string().optional()
      })),
      warnings: z.array(z.object({
        field: z.string(),
        warning: z.string(),
        value: z.string().optional()
      })),
      validated_fields: z.number(),
      total_fields: z.number()
    }
  }, async ({ form_data, validation_rules, strict_mode }) => {
    try {
      const result = await validateFormData(form_data, validation_rules, strict_mode);

      return {
        content: [{ type: "text", text: `Form validation completed. ${result.valid ? 'Valid' : 'Invalid'} - ${result.errors.length} errors, ${result.warnings.length} warnings.` }],
        structuredContent: {
          success: true,
          valid: result.valid,
          errors: result.errors,
          warnings: result.warnings,
          validated_fields: result.validatedFields,
          total_fields: result.totalFields
        }
      };

    } catch (error) {
      return {
        content: [{ type: "text", text: `Form validation failed: ${error instanceof Error ? error.message : 'Unknown error'}` }],
        structuredContent: {
          success: false,
          error: `Form validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
          valid: false,
          errors: [],
          warnings: [],
          validated_fields: 0,
          total_fields: 0
        }
      };
    }
  });

  // Form Pattern Recognition Tool
  server.registerTool("mcp_mcp-god-mode_form_pattern_recognition", {
    description: "Recognize common form patterns (contact, registration, login, checkout) and suggest appropriate field mappings",
    inputSchema: {
      url: z.string().describe("URL of the page containing the form"),
      form_selector: z.string().optional().describe("CSS selector for specific form"),
      timeout: z.number().min(5000).max(60000).default(30000).describe("Timeout in milliseconds")
    },
    outputSchema: {
      success: z.boolean(),
      detected_patterns: z.array(z.object({
        pattern_name: z.string(),
        confidence: z.number(),
        matched_fields: z.array(z.string()),
        suggested_mapping: z.record(z.string())
      })),
      form_analysis: z.object({
        total_fields: z.number(),
        required_fields: z.number(),
        field_types: z.record(z.number()),
        complexity_score: z.number()
      }),
      error: z.string().optional()
    }
  }, async ({ url, form_selector, timeout }) => {
    try {
      const result = await recognizeFormPatterns(url, form_selector, timeout);

      return {
        content: [{ type: "text", text: `Form pattern recognition completed. Found ${result.patterns.length} patterns.` }],
        structuredContent: {
          success: true,
          detected_patterns: result.patterns,
          form_analysis: result.analysis
        }
      };

    } catch (error) {
      return {
        content: [{ type: "text", text: `Form pattern recognition failed: ${error instanceof Error ? error.message : 'Unknown error'}` }],
        structuredContent: {
          success: false,
          error: `Form pattern recognition failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
          detected_patterns: [],
          form_analysis: {
            total_fields: 0,
            required_fields: 0,
            field_types: {},
            complexity_score: 0
          }
        }
      };
    }
  });
}

// Helper functions
async function detectBrowserEngine(): Promise<string> {
  const engines = [
    { name: 'playwright', command: 'npx playwright --version' },
    { name: 'puppeteer', command: 'npx puppeteer --version' },
    { name: 'chrome', command: 'google-chrome --version || chromium --version || chrome --version' }
  ];

  for (const engine of engines) {
    try {
      await execAsync(engine.command);
      return engine.name;
    } catch (error) {
      continue;
    }
  }
  throw new Error("No browser engine available. Please install Playwright, Puppeteer, or Chrome.");
}

async function launchBrowser(engine: string, headless: boolean = true) {
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

async function detectForms(url: string, formSelector?: string, timeout: number = 30000, saveScreenshot: boolean = true) {
  const engine = await detectBrowserEngine();
  const browser = await launchBrowser(engine, false);
  
  try {
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout });
    
    const title = await page.title();
    let screenshotPath = '';
    
    if (saveScreenshot) {
      screenshotPath = `./form_detection_${Date.now()}.png`;
      await page.screenshot({ path: screenshotPath, fullPage: true });
    }
    
    // Detect forms
    const forms = await (page as any).evaluate((selector: string) => {
      const formElements = selector ? document.querySelectorAll(selector) : document.querySelectorAll('form');
      const forms = [];
      
      formElements.forEach((form, index) => {
        const fields = [];
        const inputs = form.querySelectorAll('input, textarea, select');
        
        inputs.forEach(input => {
          const field = {
            name: (input as any).name || (input as any).id || `field_${index}`,
            type: (input as any).type || (input as any).tagName.toLowerCase(),
            required: (input as any).required || (input as any).hasAttribute('required'),
            placeholder: (input as any).placeholder || '',
            value: (input as any).value || '',
            options: [],
            validation: ''
          };
          
          // Handle select options
          if (input.tagName.toLowerCase() === 'select') {
            const options = input.querySelectorAll('option');
            field.options = Array.from(options).map(option => (option as any).textContent || '');
          }
          
          // Detect validation patterns
          if ((input as any).pattern) {
            field.validation = (input as any).pattern;
          }
          
          fields.push(field);
        });
        
        forms.push({
          form_id: form.id || `form_${index}`,
          form_class: form.className || '',
          form_action: (form as any).action || '',
          form_method: (form as any).method || 'get',
          fields,
          complexity: fields.length > 10 ? 'high' : fields.length > 5 ? 'medium' : 'low'
        });
      });
      
      return forms;
    }, formSelector);
    
    return {
      forms,
      screenshot: screenshotPath,
      title
    };
  } finally {
    await browser.close();
  }
}

async function completeForm(url: string, formData: Record<string, string>, formSelector?: string, captchaHandling: string = 'auto', validation: boolean = true, submitForm: boolean = false, timeout: number = 60000, saveScreenshot: boolean = true) {
  const engine = await detectBrowserEngine();
  const browser = await launchBrowser(engine, false);
  
  try {
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout });
    
    let fieldsFilled = 0;
    let fieldsDetected = 0;
    let captchaSolved = false;
    let formSubmitted = false;
    let validationErrors: string[] = [];
    let screenshotPath = '';
    
    const summary = {
      successfulFields: [] as string[],
      failedFields: [] as string[],
      skippedFields: [] as string[],
      captchaStatus: ''
    };
    
    // Get form element
    const formElement = formSelector ? await (page as any).$(formSelector) : await (page as any).$('form');
    if (!formElement) {
      throw new Error('No form found on the page');
    }
    
    // Detect all form fields
    const detectedFields = await (page as any).evaluate((selector: string) => {
      const form = selector ? document.querySelector(selector) : document.querySelector('form');
      if (!form) return [];
      
      const inputs = form.querySelectorAll('input, textarea, select');
      return Array.from(inputs).map(input => ({
        name: (input as any).name || (input as any).id || '',
        type: (input as any).type || (input as any).tagName.toLowerCase(),
        required: (input as any).required || (input as any).hasAttribute('required')
      }));
    }, formSelector);
    
    fieldsDetected = detectedFields.length;
    
    // Fill form fields
    for (const [fieldName, value] of Object.entries(formData)) {
      try {
        const field = await (page as any).$(`input[name="${fieldName}"], textarea[name="${fieldName}"], select[name="${fieldName}"], input[id="${fieldName}"], textarea[id="${fieldName}"], select[id="${fieldName}"]`);
        
        if (field) {
          const fieldType = await field.getAttribute('type') || await field.evaluate(el => el.tagName.toLowerCase());
          
          switch (fieldType) {
            case 'text':
            case 'email':
            case 'password':
            case 'number':
            case 'tel':
            case 'url':
              await field.fill(value);
              break;
            case 'textarea':
              await field.fill(value);
              break;
            case 'checkbox':
              if (value.toLowerCase() === 'true' || value.toLowerCase() === 'checked') {
                await field.check();
              }
              break;
            case 'radio':
              await field.check();
              break;
            case 'select':
              await field.selectOption(value);
              break;
            case 'file':
              // Handle file uploads
              await field.setInputFiles(value);
              break;
            default:
              await field.fill(value);
          }
          
          fieldsFilled++;
          summary.successfulFields.push(fieldName);
        } else {
          summary.failedFields.push(fieldName);
        }
      } catch (error) {
        summary.failedFields.push(fieldName);
        console.error(`Failed to fill field ${fieldName}:`, error instanceof Error ? error.message : 'Unknown error');
      }
    }
    
    // Handle CAPTCHA if present
    if (captchaHandling !== 'skip') {
      try {
        const captchaResult = await handleCaptcha(page, captchaHandling);
        if (captchaResult.solved) {
          captchaSolved = true;
          summary.captchaStatus = 'solved';
        } else {
          summary.captchaStatus = 'failed';
        }
      } catch (error) {
        summary.captchaStatus = 'error';
        console.error('CAPTCHA handling failed:', error.message);
      }
    }
    
    // Validate form if requested
    if (validation) {
      const errors = await (page as any).evaluate(() => {
        const errorElements = document.querySelectorAll('.error, .invalid, [aria-invalid="true"], .field-error');
        return Array.from(errorElements).map(el => el.textContent || '');
      });
      validationErrors = errors.filter((error: string) => error.trim());
    }
    
    // Submit form if requested and no validation errors
    if (submitForm && validationErrors.length === 0) {
      try {
        const submitButton = await (page as any).$('button[type="submit"], input[type="submit"], button:not([type])');
        if (submitButton) {
          await submitButton.click();
          await page.waitForNavigation({ timeout: 10000 });
          formSubmitted = true;
        }
      } catch (error) {
        console.error('Form submission failed:', error instanceof Error ? error.message : 'Unknown error');
      }
    }
    
    // Take final screenshot
    if (saveScreenshot) {
      screenshotPath = `./form_completion_${Date.now()}.png`;
      await page.screenshot({ path: screenshotPath, fullPage: true });
    }
    
    return {
      fieldsFilled,
      fieldsDetected,
      captchaSolved,
      formSubmitted,
      screenshot: screenshotPath,
      validationErrors,
      summary
    };
  } finally {
    await browser.close();
  }
}

async function validateFormData(formData: Record<string, string>, validationRules?: Record<string, any>, strictMode: boolean = false) {
  const errors: Array<{field: string, error: string, value?: string}> = [];
  const warnings: Array<{field: string, warning: string, value?: string}> = [];
  let validatedFields = 0;
  const totalFields = Object.keys(formData).length;
  
  for (const [fieldName, value] of Object.entries(formData)) {
    validatedFields++;
    
    // Check if field is required
    const isRequired = validationRules?.[fieldName]?.required || false;
    if (isRequired && (!value || value.trim() === '')) {
      errors.push({
        field: fieldName,
        error: VALIDATION_RULES.required.message,
        value
      });
      continue;
    }
    
    // Skip validation for empty optional fields
    if (!value || value.trim() === '') {
      continue;
    }
    
    // Apply field-specific validation
    const fieldRules = validationRules?.[fieldName];
    if (fieldRules) {
      // Type validation
      if (fieldRules.type === 'email' && !VALIDATION_RULES.email.pattern.test(value)) {
        errors.push({
          field: fieldName,
          error: VALIDATION_RULES.email.message,
          value
        });
      }
      
      if (fieldRules.type === 'phone' && !VALIDATION_RULES.phone.pattern.test(value)) {
        errors.push({
          field: fieldName,
          error: VALIDATION_RULES.phone.message,
          value
        });
      }
      
      // Length validation
      if (fieldRules.min_length && value.length < fieldRules.min_length) {
        errors.push({
          field: fieldName,
          error: `Minimum length is ${fieldRules.min_length} characters`,
          value
        });
      }
      
      if (fieldRules.max_length && value.length > fieldRules.max_length) {
        errors.push({
          field: fieldName,
          error: `Maximum length is ${fieldRules.max_length} characters`,
          value
        });
      }
      
      // Pattern validation
      if (fieldRules.pattern) {
        const pattern = new RegExp(fieldRules.pattern);
        if (!pattern.test(value)) {
          errors.push({
            field: fieldName,
            error: 'Value does not match required pattern',
            value
          });
        }
      }
    }
    
    // Auto-detect field types and apply validation
    if (fieldName.toLowerCase().includes('email') && !VALIDATION_RULES.email.pattern.test(value)) {
      if (strictMode) {
        errors.push({
          field: fieldName,
          error: VALIDATION_RULES.email.message,
          value
        });
      } else {
        warnings.push({
          field: fieldName,
          warning: 'This appears to be an email field but the format may be invalid',
          value
        });
      }
    }
    
    if (fieldName.toLowerCase().includes('phone') && !VALIDATION_RULES.phone.pattern.test(value)) {
      if (strictMode) {
        errors.push({
          field: fieldName,
          error: VALIDATION_RULES.phone.message,
          value
        });
      } else {
        warnings.push({
          field: fieldName,
          warning: 'This appears to be a phone field but the format may be invalid',
          value
        });
      }
    }
  }
  
  return {
    valid: errors.length === 0,
    errors,
    warnings,
    validatedFields,
    totalFields
  };
}

async function recognizeFormPatterns(url: string, formSelector?: string, timeout: number = 30000) {
  const engine = await detectBrowserEngine();
  const browser = await launchBrowser(engine, true);
  
  try {
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout });
    
    // Analyze form structure
    const formAnalysis = await (page as any).evaluate((selector: string) => {
      const form = selector ? document.querySelector(selector) : document.querySelector('form');
      if (!form) return null;
      
      const inputs = form.querySelectorAll('input, textarea, select');
      const fields = Array.from(inputs).map(input => ({
        name: ((input as any).name || (input as any).id || '').toLowerCase(),
        type: (input as any).type || (input as any).tagName.toLowerCase(),
        required: (input as any).required || (input as any).hasAttribute('required')
      }));
      
      const fieldTypes: Record<string, number> = {};
      fields.forEach(field => {
        fieldTypes[field.type] = (fieldTypes[field.type] || 0) + 1;
      });
      
      return {
        totalFields: fields.length,
        requiredFields: fields.filter(f => f.required).length,
        fieldTypes,
        fieldNames: fields.map(f => f.name)
      };
    }, formSelector);
    
    if (!formAnalysis) {
      throw new Error('No form found on the page');
    }
    
    // Calculate complexity score
    const complexityScore = Math.min(10, formAnalysis.totalFields + (formAnalysis.requiredFields * 0.5));
    
    // Detect patterns
    const patterns = [];
    
    for (const [patternName, patternConfig] of Object.entries(FORM_PATTERNS)) {
      let confidence = 0;
      const matchedFields: string[] = [];
      const suggestedMapping: Record<string, string> = {};
      
      // Check field matches
      for (const [expectedField, fieldConfig] of Object.entries(patternConfig.fields)) {
        for (const fieldName of formAnalysis.fieldNames) {
          for (const pattern of fieldConfig.patterns) {
            if (fieldName.includes(pattern)) {
              confidence += 0.2;
              matchedFields.push(fieldName);
              suggestedMapping[expectedField] = fieldName;
              break;
            }
          }
        }
      }
      
      // Normalize confidence
      confidence = Math.min(1.0, confidence / Object.keys(patternConfig.fields).length);
      
      if (confidence > 0.3) {
        patterns.push({
          pattern_name: patternConfig.name,
          confidence,
          matched_fields: matchedFields,
          suggested_mapping: suggestedMapping
        });
      }
    }
    
    // Sort patterns by confidence
    patterns.sort((a, b) => b.confidence - a.confidence);
    
    return {
      patterns,
      analysis: {
        total_fields: formAnalysis.totalFields,
        required_fields: formAnalysis.requiredFields,
        field_types: formAnalysis.fieldTypes,
        complexity_score: complexityScore
      }
    };
  } finally {
    await browser.close();
  }
}

async function handleCaptcha(page: any, handling: string): Promise<{solved: boolean, method?: string}> {
  // This is a simplified implementation
  // In practice, you would integrate with the CAPTCHA defeating tool
  
  try {
    // Check for common CAPTCHA types
    const captchaSelectors = [
      'iframe[src*="recaptcha"]',
      '.g-recaptcha',
      'iframe[src*="hcaptcha"]',
      '.h-captcha',
      'img[src*="captcha"]',
      '.captcha-image'
    ];
    
    for (const selector of captchaSelectors) {
      const captchaElement = await page.$(selector);
      if (captchaElement) {
        console.log(`CAPTCHA detected: ${selector}`);
        
        switch (handling) {
          case 'solve':
            // Attempt to solve CAPTCHA
            return { solved: false, method: 'solving_failed' };
            
          case 'skip':
            return { solved: true, method: 'skipped' };
            
          case 'manual':
            return { solved: false, method: 'manual_required' };
            
          default:
            return { solved: false, method: 'auto_failed' };
        }
      }
    }
    
    return { solved: true, method: 'no_captcha' };
  } catch (error) {
    return { solved: false, method: 'error' };
  }
}
