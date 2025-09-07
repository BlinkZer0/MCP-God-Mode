/**
 * Interactive provider configuration wizard
 * Helps users set up custom AI service providers by capturing selectors
 */

import inquirer from 'inquirer';
import chalk from 'chalk';
import { Driver, getDriver, DriverConfig } from '../drivers/driver-bridge';
import { ProviderConfig, ProviderManager } from '../providers/registry';

export interface WizardOptions {
  startUrl: string;
  providerName: string;
  platform: 'desktop' | 'android' | 'ios';
  headless?: boolean;
}

export interface WizardResult {
  providerId: string;
  config: ProviderConfig;
  success: boolean;
  error?: string;
}

export class ProviderWizard {
  private driver: Driver | null = null;
  private providerManager: ProviderManager;

  constructor(providerManager: ProviderManager) {
    this.providerManager = providerManager;
  }

  /**
   * Run the interactive provider setup wizard
   */
  async runWizard(options: WizardOptions): Promise<WizardResult> {
    console.log(chalk.blue('\n🔧 Provider Configuration Wizard'));
    console.log(chalk.gray(`Setting up: ${options.providerName}`));
    console.log(chalk.gray(`URL: ${options.startUrl}`));
    console.log(chalk.gray(`Platform: ${options.platform}\n`));

    try {
      // Initialize driver
      const driverConfig: DriverConfig = {
        platform: options.platform,
        headless: options.headless ?? false
      };
      this.driver = await getDriver(driverConfig);

      // Step 1: Navigate to the provider URL
      console.log(chalk.yellow('📱 Opening browser...'));
      await this.driver.open(options.startUrl);
      await this.waitForUser('Press Enter when the page has loaded and you can see the chat interface...');

      // Step 2: Capture login signal
      console.log(chalk.yellow('\n🔐 Login Detection'));
      const loginSignal = await this.captureSelector(
        'Click on the text input field where you would type a message (this helps detect if you\'re logged in)'
      );

      // Step 3: Capture input selector
      console.log(chalk.yellow('\n✏️  Input Field'));
      const inputSelector = await this.captureSelector(
        'Click on the text input field where you type messages to the AI'
      );

      // Step 4: Capture send action
      console.log(chalk.yellow('\n📤 Send Action'));
      const sendAction = await this.captureSendAction();

      // Step 5: Test the setup
      console.log(chalk.yellow('\n🧪 Testing Setup'));
      const testResult = await this.testProvider({
        loginSignal,
        input: inputSelector,
        send: sendAction
      });

      if (!testResult.success) {
        throw new Error(`Test failed: ${testResult.error}`);
      }

      // Step 6: Capture assistant container
      console.log(chalk.yellow('\n📝 Response Container'));
      const assistantContainer = await this.captureSelector(
        'Click on the area where the AI\'s response appears (the main response container)'
      );

      // Step 7: Finalize configuration
      const config = await this.finalizeConfig(options, {
        loginSignal,
        input: inputSelector,
        send: sendAction,
        assistantContainer
      });

      // Step 8: Save configuration
      const providerId = await this.saveConfiguration(options.providerName, config);

      console.log(chalk.green('\n✅ Provider configuration completed successfully!'));
      console.log(chalk.blue(`Provider ID: ${providerId}`));

      return {
        providerId,
        config,
        success: true
      };

    } catch (error) {
      console.error(chalk.red('\n❌ Wizard failed:'), error);
      return {
        providerId: '',
        config: {} as ProviderConfig,
        success: false,
        error: error instanceof Error ? error.message : String(error)
      };
    } finally {
      if (this.driver) {
        await this.driver.close();
      }
    }
  }

  /**
   * Capture a CSS selector by having the user click an element
   */
  private async captureSelector(instruction: string): Promise<string> {
    console.log(chalk.cyan(instruction));
    await this.waitForUser('Press Enter when ready to capture the selector...');

    if (!this.driver) throw new Error('Driver not initialized');

    // Inject selector capture script
    const selector = await (this.driver as any).evaluate(() => {
      return new Promise((resolve) => {
        let captured = false;

        const captureClick = (e: MouseEvent) => {
          if (captured) return;
          captured = true;

          const target = e.target as Element;
          const selector = generateSelector(target);
          
          // Remove event listeners
          document.removeEventListener('click', captureClick, true);
          
          resolve(selector);
        };

        document.addEventListener('click', captureClick, true);

        // Generate stable selector
        function generateSelector(element: Element): string {
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
        }
      });
    });

    console.log(chalk.green(`✅ Captured selector: ${selector}`));
    return selector;
  }

  /**
   * Capture send action (button click or key press)
   */
  private async captureSendAction(): Promise<{ gesture?: string; button?: string }> {
    const { action } = await inquirer.prompt([
      {
        type: 'list',
        name: 'action',
        message: 'How do you send messages?',
        choices: [
          { name: 'Press Enter key', value: 'enter' },
          { name: 'Click a send button', value: 'button' }
        ]
      }
    ]);

    if (action === 'enter') {
      return { gesture: 'enter' };
    } else {
      const buttonSelector = await this.captureSelector(
        'Click on the send button'
      );
      return { button: buttonSelector };
    }
  }

  /**
   * Test the provider configuration
   */
  private async testProvider(config: Partial<ProviderConfig>): Promise<{ success: boolean; error?: string }> {
    try {
      if (!this.driver) throw new Error('Driver not initialized');

      // Test input field
      await this.driver.fill(config.input!, 'Test message');
      console.log(chalk.green('✅ Input field test passed'));

      // Test send action
      if (config.send?.gesture === 'enter') {
        await this.driver.press('Enter');
      } else if (config.send?.button) {
        await this.driver.click(config.send.button);
      }
      console.log(chalk.green('✅ Send action test passed'));

      // Wait a moment for response
      await new Promise(resolve => setTimeout(resolve, 2000));

      return { success: true };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Finalize the provider configuration
   */
  private async finalizeConfig(
    options: WizardOptions,
    captured: {
      loginSignal: string;
      input: string;
      send: { gesture?: string; button?: string };
      assistantContainer: string;
    }
  ): Promise<ProviderConfig> {
    const { capabilities } = await inquirer.prompt([
      {
        type: 'checkbox',
        name: 'capabilities',
        message: 'What capabilities does this provider support?',
        choices: [
          { name: 'Streaming responses', value: 'streaming' },
          { name: 'File uploads', value: 'fileUpload' },
          { name: 'Code execution', value: 'codeExecution' },
          { name: 'Image generation', value: 'imageGeneration' }
        ],
        default: ['streaming']
      }
    ]);

    return {
      name: options.providerName,
      url: options.startUrl,
      loginSignal: captured.loginSignal,
      input: captured.input,
      send: captured.send,
      assistantContainer: captured.assistantContainer,
      completionSignals: ['typing', 'loading', 'thinking'],
      platforms: [options.platform],
      capabilities: {
        streaming: capabilities.includes('streaming'),
        fileUpload: capabilities.includes('fileUpload'),
        codeExecution: capabilities.includes('codeExecution'),
        imageGeneration: capabilities.includes('imageGeneration')
      }
    };
  }

  /**
   * Save the provider configuration
   */
  private async saveConfiguration(providerName: string, config: ProviderConfig): Promise<string> {
    // Generate provider ID
    const providerId = providerName.toLowerCase().replace(/[^a-z0-9]/g, '_');
    
    // Save to registry
    this.providerManager.setProvider(providerId, config);
    await this.providerManager.saveProviders();

    return providerId;
  }

  /**
   * Wait for user input
   */
  private async waitForUser(message: string): Promise<void> {
    await inquirer.prompt([
      {
        type: 'input',
        name: 'continue',
        message: message
      }
    ]);
  }
}

/**
 * Quick setup wizard for common providers
 */
export class QuickSetupWizard {
  private providerManager: ProviderManager;

  constructor(providerManager: ProviderManager) {
    this.providerManager = providerManager;
  }

  /**
   * Quick setup for a custom provider
   */
  async quickSetup(): Promise<WizardResult> {
    const { providerName, startUrl, platform } = await inquirer.prompt([
      {
        type: 'input',
        name: 'providerName',
        message: 'What is the name of this AI provider?',
        validate: (input) => input.length > 0 || 'Provider name is required'
      },
      {
        type: 'input',
        name: 'startUrl',
        message: 'What is the URL of the chat interface?',
        validate: (input) => {
          try {
            new URL(input);
            return true;
          } catch {
            return 'Please enter a valid URL';
          }
        }
      },
      {
        type: 'list',
        name: 'platform',
        message: 'Which platform are you setting up for?',
        choices: [
          { name: 'Desktop (Windows/macOS/Linux)', value: 'desktop' },
          { name: 'Android', value: 'android' },
          { name: 'iOS', value: 'ios' }
        ]
      }
    ]);

    const wizard = new ProviderWizard(this.providerManager);
    return await wizard.runWizard({
      providerName,
      startUrl,
      platform
    });
  }
}
