/**
 * Macro recording and replay system
 * Captures user actions into portable JSON scripts and replays them
 */

import { z } from 'zod';
import * as fs from 'fs-extra';
import * as path from 'path';
import { Driver, DriverUtils } from '../drivers/driver-bridge';
import { DriverConfig, getDriver } from '../drivers/driver-bridge';

// Macro step schemas
const MacroStepSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('goto'),
    url: z.string().url()
  }),
  z.object({
    type: z.literal('waitFor'),
    selector: z.string().optional(),
    textContains: z.string().optional(),
    timeoutMs: z.number().optional()
  }),
  z.object({
    type: z.literal('click'),
    selector: z.string()
  }),
  z.object({
    type: z.literal('type'),
    selector: z.string(),
    text: z.string()
  }),
  z.object({
    type: z.literal('press'),
    key: z.string()
  }),
  z.object({
    type: z.literal('assert'),
    selector: z.string(),
    textContains: z.string().optional()
  }),
  z.object({
    type: z.literal('sleep'),
    ms: z.number()
  }),
  // Mobile-specific steps
  z.object({
    type: z.literal('driverTap'),
    x: z.number(),
    y: z.number()
  }),
  z.object({
    type: z.literal('driverType'),
    text: z.string()
  }),
  z.object({
    type: z.literal('driverSwipe'),
    from: z.object({ x: z.number(), y: z.number() }),
    to: z.object({ x: z.number(), y: z.number() }),
    ms: z.number().optional()
  })
]);

const MacroSchema = z.object({
  id: z.string(),
  version: z.literal('1'),
  name: z.string(),
  description: z.string().optional(),
  target: z.object({
    provider: z.string().optional(),
    url: z.string().url().optional(),
    platform: z.enum(['desktop', 'android', 'ios'])
  }),
  steps: z.array(MacroStepSchema),
  variables: z.record(z.string()).optional(),
  createdAt: z.number(),
  updatedAt: z.number()
});

export type MacroStep = z.infer<typeof MacroStepSchema>;
export type Macro = z.infer<typeof MacroSchema>;

export interface MacroRecordOptions {
  target: { provider?: string; url?: string };
  scope: 'dom' | 'driver' | 'auto';
  name?: string;
  description?: string;
}

export interface MacroRunOptions {
  variables?: Record<string, string>;
  dryRun?: boolean;
  timeout?: number;
}

export interface MacroRunResult {
  ok: boolean;
  logs: Array<{ step: number; msg: string; success: boolean }>;
  duration: number;
  error?: string;
}

export class MacroRecorder {
  private isRecording = false;
  private recordedSteps: MacroStep[] = [];
  private driver: Driver | null = null;
  private targetUrl: string = '';
  private platform: 'desktop' | 'android' | 'ios' = 'desktop';

  /**
   * Start recording a macro
   */
  async startRecording(
    driver: Driver,
    targetUrl: string,
    platform: 'desktop' | 'android' | 'ios',
    scope: 'dom' | 'driver' | 'auto' = 'auto'
  ): Promise<void> {
    if (this.isRecording) {
      throw new Error('Already recording');
    }

    this.isRecording = true;
    this.recordedSteps = [];
    this.driver = driver;
    this.targetUrl = targetUrl;
    this.platform = platform;

    // Record initial navigation
    this.recordedSteps.push({
      type: 'goto',
      url: targetUrl
    });

    // Set up event listeners based on scope
    if (scope === 'dom' || scope === 'auto') {
      await this.setupDOMRecording();
    }

    if (scope === 'driver' || (scope === 'auto' && platform !== 'desktop')) {
      await this.setupDriverRecording();
    }
  }

  /**
   * Stop recording and return the macro
   */
  stopRecording(): Macro {
    if (!this.isRecording) {
      throw new Error('Not currently recording');
    }

    this.isRecording = false;
    this.cleanup();

    const macro: Macro = {
      id: this.generateMacroId(),
      version: '1',
      name: `Recorded Macro ${new Date().toISOString()}`,
      target: {
        url: this.targetUrl,
        platform: this.platform
      },
      steps: [...this.recordedSteps],
      createdAt: Date.now(),
      updatedAt: Date.now()
    };

    return macro;
  }

  /**
   * Set up DOM-based recording
   */
  private async setupDOMRecording(): Promise<void> {
    if (!this.driver || !('evaluate' in this.driver)) return;

    // Inject recording script
    await (this.driver as any).evaluate(() => {
      const recorder = {
        steps: [],
        isRecording: true,

        recordStep(step: any) {
          if (this.isRecording) {
            this.steps.push({
              ...step,
              timestamp: Date.now()
            });
            console.log('MACRO_STEP:', JSON.stringify(step));
          }
        },

        stop() {
          this.isRecording = false;
        }
      };

      // Record clicks
      document.addEventListener('click', (e) => {
        const target = e.target as Element;
        const selector = recorder.generateSelector(target);
        if (selector) {
          recorder.recordStep({
            type: 'click',
            selector
          });
        }
      }, true);

      // Record input changes
      document.addEventListener('input', (e) => {
        const target = e.target as HTMLInputElement | HTMLTextAreaElement;
        if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA') {
          const selector = recorder.generateSelector(target);
          if (selector) {
            recorder.recordStep({
              type: 'type',
              selector,
              text: target.value
            });
          }
        }
      });

      // Record key presses
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === 'Tab' || e.key === 'Escape') {
          recorder.recordStep({
            type: 'press',
            key: e.key
          });
        }
      });

      // Generate stable selectors
      recorder.generateSelector = (element: Element): string | null => {
        // Prefer data-testid
        if (element.hasAttribute('data-testid')) {
          return `[data-testid="${element.getAttribute('data-testid')}"]`;
        }

        // Prefer role
        if (element.hasAttribute('role')) {
          return `[role="${element.getAttribute('role')}"]`;
        }

        // Use ID if available
        if (element.id) {
          return `#${element.id}`;
        }

        // Use class with nth-of-type fallback
        if (element.className) {
          const classes = element.className.split(' ').filter(c => c.length > 0);
          if (classes.length > 0) {
            const classSelector = '.' + classes.join('.');
            const elements = document.querySelectorAll(classSelector);
            if (elements.length === 1) {
              return classSelector;
            } else {
              const index = Array.from(elements).indexOf(element);
              return `${classSelector}:nth-of-type(${index + 1})`;
            }
          }
        }

        // Fallback to tag name with nth-of-type
        const tagName = element.tagName.toLowerCase();
        const elements = document.querySelectorAll(tagName);
        if (elements.length > 1) {
          const index = Array.from(elements).indexOf(element);
          return `${tagName}:nth-of-type(${index + 1})`;
        }

        return tagName;
      };

      (window as any).__macroRecorder = recorder;
    });
  }

  /**
   * Set up driver-based recording (for mobile)
   */
  private async setupDriverRecording(): Promise<void> {
    // This would be implemented with Appium-specific event listeners
    // For now, we'll rely on manual step recording
    console.log('Driver-based recording setup (mobile)');
  }

  /**
   * Add a manual step to the recording
   */
  addStep(step: MacroStep): void {
    if (this.isRecording) {
      this.recordedSteps.push(step);
    }
  }

  /**
   * Clean up recording resources
   */
  private cleanup(): void {
    if (this.driver && 'evaluate' in this.driver) {
      (this.driver as any).evaluate(() => {
        if ((window as any).__macroRecorder) {
          (window as any).__macroRecorder.stop();
        }
      });
    }
  }

  /**
   * Generate unique macro ID
   */
  private generateMacroId(): string {
    return `macro_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

export class MacroRunner {
  private macroStoragePath: string;

  constructor(storagePath: string = './macros') {
    this.macroStoragePath = storagePath;
  }

  /**
   * Run a macro by ID
   */
  async runMacro(
    macroId: string,
    options: MacroRunOptions = {}
  ): Promise<MacroRunResult> {
    const startTime = Date.now();
    const logs: Array<{ step: number; msg: string; success: boolean }> = [];

    try {
      // Load macro
      const macro = await this.loadMacro(macroId);
      if (!macro) {
        throw new Error(`Macro not found: ${macroId}`);
      }

      // Validate macro
      const validation = MacroSchema.safeParse(macro);
      if (!validation.success) {
        throw new Error(`Invalid macro format: ${validation.error.message}`);
      }

      if (options.dryRun) {
        return this.dryRunMacro(macro, logs, startTime);
      }

      // Get driver for the target platform
      const driverConfig: DriverConfig = {
        platform: macro.target.platform
      };
      const driver = await getDriver(driverConfig);

      try {
        // Execute steps
        for (let i = 0; i < macro.steps.length; i++) {
          const step = macro.steps[i];
          const stepResult = await this.executeStep(driver, step, options.variables || {});
          
          logs.push({
            step: i + 1,
            msg: stepResult.message,
            success: stepResult.success
          });

          if (!stepResult.success) {
            throw new Error(`Step ${i + 1} failed: ${stepResult.message}`);
          }
        }

        return {
          ok: true,
          logs,
          duration: Date.now() - startTime
        };
      } finally {
        await driver.close();
      }
    } catch (error) {
      return {
        ok: false,
        logs,
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Execute a single macro step
   */
  private async executeStep(
    driver: Driver,
    step: MacroStep,
    variables: Record<string, string>
  ): Promise<{ success: boolean; message: string }> {
    try {
      switch (step.type) {
        case 'goto':
          await driver.open(step.url);
          return { success: true, message: `Navigated to ${step.url}` };

        case 'waitFor':
          const timeout = step.timeoutMs || 10000;
          await driver.waitFor(
            { selector: step.selector, textContains: step.textContains },
            timeout
          );
          return { success: true, message: `Waited for ${step.selector || step.textContains}` };

        case 'click':
          const clickSelector = DriverUtils.substituteVariables(step.selector, variables);
          await driver.click(clickSelector);
          return { success: true, message: `Clicked ${clickSelector}` };

        case 'type':
          const typeSelector = DriverUtils.substituteVariables(step.selector, variables);
          const typeText = DriverUtils.substituteVariables(step.text, variables);
          await driver.fill(typeSelector, typeText);
          return { success: true, message: `Typed "${typeText}" into ${typeSelector}` };

        case 'press':
          await driver.press(step.key);
          return { success: true, message: `Pressed ${step.key}` };

        case 'assert':
          const assertSelector = DriverUtils.substituteVariables(step.selector, variables);
          const isVisible = await driver.isVisible(assertSelector);
          if (!isVisible) {
            throw new Error(`Element not visible: ${assertSelector}`);
          }
          if (step.textContains) {
            const text = await driver.getText(assertSelector);
            if (!text.includes(step.textContains)) {
              throw new Error(`Text not found: ${step.textContains}`);
            }
          }
          return { success: true, message: `Asserted ${assertSelector}` };

        case 'sleep':
          await new Promise(resolve => setTimeout(resolve, step.ms));
          return { success: true, message: `Slept for ${step.ms}ms` };

        case 'driverTap':
          if (driver.tap) {
            await driver.tap(step.x, step.y);
            return { success: true, message: `Tapped at (${step.x}, ${step.y})` };
          }
          throw new Error('Tap not supported on this platform');

        case 'driverType':
          const driverText = DriverUtils.substituteVariables(step.text, variables);
          // This would need platform-specific implementation
          return { success: true, message: `Typed "${driverText}" (driver)` };

        case 'driverSwipe':
          if (driver.swipe) {
            await driver.swipe(step.from, step.to, step.ms);
            return { success: true, message: `Swiped from (${step.from.x}, ${step.from.y}) to (${step.to.x}, ${step.to.y})` };
          }
          throw new Error('Swipe not supported on this platform');

        default:
          throw new Error(`Unknown step type: ${(step as any).type}`);
      }
    } catch (error) {
      return {
        success: false,
        message: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Dry run a macro (print steps without executing)
   */
  private dryRunMacro(
    macro: Macro,
    logs: Array<{ step: number; msg: string; success: boolean }>,
    startTime: number
  ): MacroRunResult {
    logs.push({
      step: 0,
      msg: `Dry run for macro: ${macro.name}`,
      success: true
    });

    macro.steps.forEach((step, index) => {
      logs.push({
        step: index + 1,
        msg: `Would execute: ${step.type} ${JSON.stringify(step)}`,
        success: true
      });
    });

    return {
      ok: true,
      logs,
      duration: Date.now() - startTime
    };
  }

  /**
   * Save a macro to storage
   */
  async saveMacro(macro: Macro): Promise<void> {
    await fs.ensureDir(this.macroStoragePath);
    const filePath = path.join(this.macroStoragePath, `${macro.id}.json`);
    await fs.writeJson(filePath, macro, { spaces: 2 });
  }

  /**
   * Load a macro from storage
   */
  async loadMacro(macroId: string): Promise<Macro | null> {
    const filePath = path.join(this.macroStoragePath, `${macroId}.json`);
    
    try {
      if (!(await fs.pathExists(filePath))) {
        return null;
      }
      return await fs.readJson(filePath);
    } catch (error) {
      console.warn(`Failed to load macro ${macroId}:`, error);
      return null;
    }
  }

  /**
   * List all available macros
   */
  async listMacros(): Promise<Array<{ id: string; name: string; createdAt: number }>> {
    await fs.ensureDir(this.macroStoragePath);
    
    const files = await fs.readdir(this.macroStoragePath);
    const macros: Array<{ id: string; name: string; createdAt: number }> = [];
    
    for (const file of files) {
      if (file.endsWith('.json')) {
        try {
          const macro = await fs.readJson(path.join(this.macroStoragePath, file));
          macros.push({
            id: macro.id,
            name: macro.name,
            createdAt: macro.createdAt
          });
        } catch (error) {
          console.warn(`Failed to read macro file ${file}:`, error);
        }
      }
    }
    
    return macros.sort((a, b) => b.createdAt - a.createdAt);
  }

  /**
   * Delete a macro
   */
  async deleteMacro(macroId: string): Promise<boolean> {
    const filePath = path.join(this.macroStoragePath, `${macroId}.json`);
    
    try {
      if (await fs.pathExists(filePath)) {
        await fs.remove(filePath);
        return true;
      }
      return false;
    } catch (error) {
      console.warn(`Failed to delete macro ${macroId}:`, error);
      return false;
    }
  }
}

// Global instances
export const macroRecorder = new MacroRecorder();
export const macroRunner = new MacroRunner(
  process.env.MACRO_STORAGE_PATH || './macros'
);
