/**
 * Puppeteer Form Submission
 *
 * Handles automated form filling with CAPTCHA detection and user interaction,
 * file uploads, and receipt capture for crime reporting.
 */
export class PuppeteerSubmitter {
    config;
    artifactManager;
    captchaDefeatingTool; // Reference to CAPTCHA defeating tool
    constructor(config, artifactManager) {
        this.config = config;
        this.artifactManager = artifactManager;
    }
    /**
     * Submit report via Puppeteer form filling
     */
    async submitReport(report, options) {
        const puppeteer = await import('puppeteer');
        const browser = await puppeteer.launch({
            headless: this.config.headless,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--no-first-run',
                '--no-zygote',
                '--disable-gpu',
                ...(this.config.args || [])
            ]
        });
        try {
            const page = await browser.newPage();
            // Configure page
            await this.configurePage(page);
            // Navigate to form
            await page.goto(report.jurisdiction.channel.urlOrAddress, {
                waitUntil: 'networkidle2',
                timeout: this.config.timeout
            });
            // Take initial screenshot
            const initialScreenshot = await this.artifactManager.captureScreenshot(page, 'initial');
            // Detect and handle CAPTCHA
            const captchaInfo = await this.detectCaptcha(page);
            if (captchaInfo) {
                const captchaResult = await this.handleCaptcha(page, captchaInfo, options);
                if (captchaResult.status === 'captcha_required') {
                    return captchaResult;
                }
            }
            // Map and fill form fields
            const fieldMappings = await this.mapFormFields(page, report);
            await this.fillFormFields(page, fieldMappings);
            // Handle file uploads
            await this.handleFileUploads(page, report.attachments);
            // Take pre-submission screenshot
            const preSubmitScreenshot = await this.artifactManager.captureScreenshot(page, 'pre-submit');
            // Submit form
            const submitResult = await this.submitForm(page);
            // Wait for confirmation
            const confirmationResult = await this.waitForConfirmation(page);
            // Capture final artifacts
            const finalScreenshot = await this.artifactManager.captureScreenshot(page, 'final');
            const pdf = await this.artifactManager.capturePDF(page, 'confirmation');
            // Extract receipt information
            const receipt = await this.extractReceipt(page);
            await browser.close();
            return {
                status: 'submitted',
                receipt,
                artifacts: {
                    screenshots: [initialScreenshot, preSubmitScreenshot, finalScreenshot],
                    pdf,
                    html: await page.content()
                },
                nextSteps: this.generateNextSteps(report, receipt)
            };
        }
        catch (error) {
            await browser.close();
            return {
                status: 'failed',
                errors: [error instanceof Error ? error.message : 'Unknown error occurred'],
                artifacts: {
                    screenshots: [await this.artifactManager.captureScreenshot(browser, 'error')]
                }
            };
        }
    }
    /**
     * Configure page settings
     */
    async configurePage(page) {
        if (this.config.userAgent) {
            await page.setUserAgent(this.config.userAgent);
        }
        if (this.config.viewport) {
            await page.setViewport(this.config.viewport);
        }
        // Set timeout
        page.setDefaultTimeout(this.config.timeout);
        // Handle console messages
        page.on('console', (msg) => {
            console.log(`Puppeteer console: ${msg.text()}`);
        });
        // Handle page errors
        page.on('pageerror', (error) => {
            console.error(`Puppeteer page error: ${error.message}`);
        });
    }
    /**
     * Detect CAPTCHA on the page
     */
    async detectCaptcha(page) {
        // Common CAPTCHA selectors
        const captchaSelectors = [
            { type: 'recaptcha', selector: '.g-recaptcha, [data-sitekey]' },
            { type: 'hcaptcha', selector: '.h-captcha, [data-sitekey]' },
            { type: 'image', selector: 'img[src*="captcha"], img[alt*="captcha"]' },
            { type: 'other', selector: '[id*="captcha"], [class*="captcha"]' }
        ];
        for (const { type, selector } of captchaSelectors) {
            const element = await page.$(selector);
            if (element) {
                const captchaInfo = {
                    type: type,
                    selector
                };
                // Get image URL for image CAPTCHAs
                if (type === 'image') {
                    const imageUrl = await page.evaluate((el) => el.src, element);
                    captchaInfo.imageUrl = imageUrl;
                }
                // Get instructions
                const instructions = await this.getCaptchaInstructions(page, selector);
                captchaInfo.instructions = instructions;
                return captchaInfo;
            }
        }
        return null;
    }
    /**
     * Get CAPTCHA instructions
     */
    async getCaptchaInstructions(page, selector) {
        try {
            // Look for instruction text near the CAPTCHA
            const instructionSelectors = [
                `${selector} + *`,
                `${selector} ~ *`,
                `${selector} + label`,
                `${selector} ~ label`,
                `[for*="captcha"]`,
                `label[for*="captcha"]`
            ];
            for (const instructionSelector of instructionSelectors) {
                const instructionElement = await page.$(instructionSelector);
                if (instructionElement) {
                    const text = await page.evaluate((el) => el.textContent, instructionElement);
                    if (text && text.trim()) {
                        return text.trim();
                    }
                }
            }
            return 'Please solve the CAPTCHA to continue';
        }
        catch (error) {
            return 'Please solve the CAPTCHA to continue';
        }
    }
    /**
     * Handle CAPTCHA resolution
     */
    async handleCaptcha(page, captchaInfo, options) {
        // If we have a CAPTCHA defeating tool, try to use it
        if (this.captchaDefeatingTool && captchaInfo.type === 'image' && captchaInfo.imageUrl) {
            try {
                const captchaResult = await this.captchaDefeatingTool.solve({
                    imageUrl: captchaInfo.imageUrl,
                    captchaType: 'image'
                });
                if (captchaResult.solution) {
                    // Fill in the CAPTCHA solution
                    const inputSelector = `${captchaInfo.selector} + input, ${captchaInfo.selector} ~ input, input[name*="captcha"]`;
                    await page.type(inputSelector, captchaResult.solution);
                    return { status: 'submitted' };
                }
            }
            catch (error) {
                console.warn('CAPTCHA solving failed, falling back to manual resolution');
            }
        }
        // Manual CAPTCHA resolution required
        return {
            status: 'captcha_required',
            captchaUrl: captchaInfo.imageUrl,
            nextSteps: [
                `CAPTCHA detected: ${captchaInfo.type}`,
                captchaInfo.instructions || 'Please solve the CAPTCHA manually',
                'Use the --headful flag to see the browser and solve the CAPTCHA',
                'Or provide CAPTCHA solving credentials in configuration'
            ],
            artifacts: {}
        };
    }
    /**
     * Map form fields to report data
     */
    async mapFormFields(page, report) {
        const fields = [];
        // Get all form inputs
        const inputs = await page.$$('input, textarea, select');
        for (const input of inputs) {
            const fieldInfo = await page.evaluate((el) => {
                return {
                    selector: el.id ? `#${el.id}` : el.name ? `[name="${el.name}"]` : null,
                    type: el.type || el.tagName.toLowerCase(),
                    name: el.name,
                    id: el.id,
                    placeholder: el.placeholder,
                    label: el.labels?.[0]?.textContent || ''
                };
            }, input);
            if (!fieldInfo.selector)
                continue;
            // Map field to report data
            const value = this.mapFieldValue(fieldInfo, report);
            if (value) {
                fields.push({
                    selector: fieldInfo.selector,
                    value,
                    type: fieldInfo.type,
                    required: fieldInfo.type === 'required'
                });
            }
        }
        return fields;
    }
    /**
     * Map field information to report value
     */
    mapFieldValue(fieldInfo, report) {
        const { name, id, placeholder, label } = fieldInfo;
        const searchText = `${name} ${id} ${placeholder} ${label}`.toLowerCase();
        // Crime type mapping
        if (searchText.includes('crime') || searchText.includes('type') || searchText.includes('offense')) {
            return report.fields.crime_type || '';
        }
        // Location mapping
        if (searchText.includes('location') || searchText.includes('address') || searchText.includes('where')) {
            return report.fields.location || '';
        }
        // Date mapping
        if (searchText.includes('date') || searchText.includes('occurred') || searchText.includes('when')) {
            return report.fields.date_occurred || '';
        }
        // Time mapping
        if (searchText.includes('time') || searchText.includes('hour')) {
            return report.fields.time_occurred || '';
        }
        // Description mapping
        if (searchText.includes('description') || searchText.includes('narrative') || searchText.includes('details') || searchText.includes('what')) {
            return report.fields.narrative || '';
        }
        // Name mapping
        if (searchText.includes('name') && !report.anonymous) {
            return report.fields.reporter_name || '';
        }
        // Phone mapping
        if (searchText.includes('phone') && !report.anonymous) {
            return report.fields.reporter_phone || '';
        }
        // Email mapping
        if (searchText.includes('email') && !report.anonymous) {
            return report.fields.reporter_email || '';
        }
        // Address mapping
        if (searchText.includes('address') && !report.anonymous) {
            return report.fields.reporter_address || '';
        }
        return null;
    }
    /**
     * Fill form fields
     */
    async fillFormFields(page, fields) {
        for (const field of fields) {
            try {
                await page.waitForSelector(field.selector, { timeout: 5000 });
                switch (field.type) {
                    case 'text':
                    case 'textarea':
                        await page.type(field.selector, field.value);
                        break;
                    case 'select':
                        await page.select(field.selector, field.value);
                        break;
                    case 'checkbox':
                        if (field.value.toLowerCase() === 'yes' || field.value.toLowerCase() === 'true') {
                            await page.check(field.selector);
                        }
                        break;
                    case 'radio':
                        await page.click(field.selector);
                        break;
                }
            }
            catch (error) {
                console.warn(`Failed to fill field ${field.selector}: ${error}`);
            }
        }
    }
    /**
     * Handle file uploads
     */
    async handleFileUploads(page, attachments) {
        const fileInputs = await page.$$('input[type="file"]');
        for (let i = 0; i < fileInputs.length && i < attachments.length; i++) {
            const attachment = attachments[i];
            if (attachment.kind === 'file') {
                try {
                    await fileInputs[i].uploadFile(attachment.path);
                }
                catch (error) {
                    console.warn(`Failed to upload file ${attachment.path}: ${error}`);
                }
            }
        }
    }
    /**
     * Submit the form
     */
    async submitForm(page) {
        // Look for submit button
        const submitSelectors = [
            'input[type="submit"]',
            'button[type="submit"]',
            'button:contains("Submit")',
            'button:contains("Send")',
            'button:contains("File")',
            'button:contains("Report")',
            '.submit-button',
            '#submit',
            '[name="submit"]'
        ];
        for (const selector of submitSelectors) {
            try {
                const submitButton = await page.$(selector);
                if (submitButton) {
                    await submitButton.click();
                    return;
                }
            }
            catch (error) {
                // Continue to next selector
            }
        }
        // Fallback: submit the form directly
        await page.evaluate(() => {
            const forms = document.querySelectorAll('form');
            if (forms.length > 0) {
                forms[0].submit();
            }
        });
    }
    /**
     * Wait for confirmation page
     */
    async waitForConfirmation(page) {
        // Wait for confirmation indicators
        const confirmationSelectors = [
            '.confirmation',
            '.success',
            '.thank-you',
            '[class*="confirm"]',
            '[class*="success"]',
            'h1:contains("Thank")',
            'h1:contains("Success")',
            'h1:contains("Submitted")'
        ];
        for (const selector of confirmationSelectors) {
            try {
                await page.waitForSelector(selector, { timeout: 10000 });
                return;
            }
            catch (error) {
                // Continue to next selector
            }
        }
        // Fallback: wait for network idle
        await page.waitForLoadState('networkidle', { timeout: 10000 });
    }
    /**
     * Extract receipt information
     */
    async extractReceipt(page) {
        try {
            // Look for reference numbers, confirmation numbers, etc.
            const receiptSelectors = [
                '.reference-number',
                '.confirmation-number',
                '.case-number',
                '[class*="reference"]',
                '[class*="confirmation"]',
                '[class*="case"]',
                'strong:contains("Reference")',
                'strong:contains("Confirmation")',
                'strong:contains("Case")'
            ];
            let referenceId;
            let confirmationNumber;
            for (const selector of receiptSelectors) {
                try {
                    const element = await page.$(selector);
                    if (element) {
                        const text = await page.evaluate((el) => el.textContent, element);
                        if (text && text.trim()) {
                            if (selector.includes('reference')) {
                                referenceId = text.trim();
                            }
                            else if (selector.includes('confirmation')) {
                                confirmationNumber = text.trim();
                            }
                            else if (selector.includes('case')) {
                                referenceId = text.trim();
                            }
                        }
                    }
                }
                catch (error) {
                    // Continue to next selector
                }
            }
            return {
                referenceId,
                confirmationNumber,
                timestamp: new Date().toISOString(),
                method: 'form'
            };
        }
        catch (error) {
            return {
                timestamp: new Date().toISOString(),
                method: 'form'
            };
        }
    }
    /**
     * Generate next steps
     */
    generateNextSteps(report, receipt) {
        const steps = [
            'Report has been submitted successfully',
            'Keep a copy of this receipt for your records'
        ];
        if (receipt?.referenceId) {
            steps.push(`Reference ID: ${receipt.referenceId}`);
        }
        if (receipt?.confirmationNumber) {
            steps.push(`Confirmation Number: ${receipt.confirmationNumber}`);
        }
        steps.push('You may be contacted by law enforcement for additional information', 'If this is an emergency, call 911 immediately');
        return steps;
    }
    /**
     * Set CAPTCHA defeating tool reference
     */
    setCaptchaDefeatingTool(tool) {
        this.captchaDefeatingTool = tool;
    }
    /**
     * Update configuration
     */
    updateConfig(config) {
        this.config = { ...this.config, ...config };
    }
}
