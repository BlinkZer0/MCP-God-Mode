import { z } from "zod";

/**
 * Form Validation Tool
 * Validate form data against field requirements, patterns, and business rules
 */
export function registerFormValidation(server: any): void {
  server.registerTool("form_validation", {
    description: "Validate form data against field requirements, patterns, and business rules",
    inputSchema: {
      form_data: z.record(z.string()).describe("Form data to validate (field_name: value pairs)"),
      validation_rules: z.record(z.object({
        required: z.boolean().optional(),
        type: z.string().optional(),
        pattern: z.string().optional(),
        min_length: z.number().optional(),
        max_length: z.number().optional(),
        custom_validation: z.string().optional()
      })).optional().describe("Custom validation rules for specific fields"),
      strict_mode: z.boolean().default(false).describe("Use strict validation mode")
    }
  }, async ({ form_data, validation_rules = {}, strict_mode = false }) => {
    try {
      const validationResults = {
        isValid: true,
        errors: [] as string[],
        warnings: [] as string[],
        fieldResults: {} as Record<string, any>
      };

      // Validate each field
      for (const [fieldName, value] of Object.entries(form_data)) {
        const fieldRules = validation_rules[fieldName] || {};
        const fieldResult = {
          isValid: true,
          errors: [] as string[],
          warnings: [] as string[]
        };

        // Ensure value is a string for validation
        const stringValue = String(value || '');

        // Required field validation
        if (fieldRules.required && (!value || stringValue.trim() === '')) {
          fieldResult.isValid = false;
          fieldResult.errors.push(`${fieldName} is required`);
          validationResults.isValid = false;
        }

        // Length validation
        if (value && fieldRules.min_length && stringValue.length < fieldRules.min_length) {
          fieldResult.isValid = false;
          fieldResult.errors.push(`${fieldName} must be at least ${fieldRules.min_length} characters`);
          validationResults.isValid = false;
        }

        if (value && fieldRules.max_length && stringValue.length > fieldRules.max_length) {
          fieldResult.isValid = false;
          fieldResult.errors.push(`${fieldName} must be no more than ${fieldRules.max_length} characters`);
          validationResults.isValid = false;
        }

        // Pattern validation
        if (value && fieldRules.pattern) {
          const regex = new RegExp(fieldRules.pattern);
          if (!regex.test(stringValue)) {
            fieldResult.isValid = false;
            fieldResult.errors.push(`${fieldName} format is invalid`);
            validationResults.isValid = false;
          }
        }

        // Type validation
        if (value && fieldRules.type) {
          switch (fieldRules.type) {
            case 'email':
              const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
              if (!emailRegex.test(stringValue)) {
                fieldResult.isValid = false;
                fieldResult.errors.push(`${fieldName} must be a valid email address`);
                validationResults.isValid = false;
              }
              break;
            case 'url':
              try {
                new URL(stringValue);
              } catch {
                fieldResult.isValid = false;
                fieldResult.errors.push(`${fieldName} must be a valid URL`);
                validationResults.isValid = false;
              }
              break;
            case 'number':
              if (isNaN(Number(stringValue))) {
                fieldResult.isValid = false;
                fieldResult.errors.push(`${fieldName} must be a valid number`);
                validationResults.isValid = false;
              }
              break;
          }
        }

        validationResults.fieldResults[fieldName] = fieldResult;
        validationResults.errors.push(...fieldResult.errors);
        validationResults.warnings.push(...fieldResult.warnings);
      }

      return {
        content: [{
          type: "text",
          text: JSON.stringify(validationResults, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: "text",
          text: `Form validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`
        }]
      };
    }
  });
}
