# Form Pattern Recognition Tool

## Overview
The **Form Pattern Recognition Tool** is a comprehensive form pattern recognition and analysis utility that provides advanced form pattern detection, field mapping, and form classification capabilities. It offers cross-platform support and enterprise-grade form pattern recognition features.

## Features
- **Pattern Recognition**: Advanced form pattern recognition and analysis
- **Field Mapping**: Comprehensive form field mapping and classification
- **Form Classification**: Advanced form classification and categorization
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Common Patterns**: Recognition of common form patterns and structures
- **Field Suggestions**: Intelligent field mapping and suggestion capabilities

## Usage

### Pattern Recognition
```bash
# Recognize form patterns
{
  "url": "https://example.com/contact",
  "form_selector": "#contact-form",
  "timeout": 30000
}

# Recognize multiple forms
{
  "url": "https://example.com/forms",
  "timeout": 30000
}

# Recognize with specific selector
{
  "url": "https://example.com/login",
  "form_selector": ".login-form",
  "timeout": 30000
}
```

### Field Mapping
```bash
# Map form fields
{
  "url": "https://example.com/contact",
  "form_selector": "#contact-form",
  "timeout": 30000
}

# Map with field suggestions
{
  "url": "https://example.com/registration",
  "form_selector": "#registration-form",
  "timeout": 30000
}

# Map with pattern analysis
{
  "url": "https://example.com/checkout",
  "form_selector": "#checkout-form",
  "timeout": 30000
}
```

### Form Classification
```bash
# Classify form type
{
  "url": "https://example.com/contact",
  "form_selector": "#contact-form",
  "timeout": 30000
}

# Classify with pattern analysis
{
  "url": "https://example.com/registration",
  "form_selector": "#registration-form",
  "timeout": 30000
}

# Classify with field analysis
{
  "url": "https://example.com/checkout",
  "form_selector": "#checkout-form",
  "timeout": 30000
}
```

## Parameters

### Recognition Parameters
- **url**: URL of the page containing the form
- **form_selector**: CSS selector for specific form
- **timeout**: Timeout in milliseconds

### Pattern Parameters
- **pattern_type**: Type of pattern to recognize
- **pattern_scope**: Scope of pattern recognition
- **pattern_depth**: Depth of pattern analysis

### Classification Parameters
- **classification_type**: Type of classification to perform
- **classification_scope**: Scope of classification
- **classification_depth**: Depth of classification analysis

## Output Format
```json
{
  "success": true,
  "result": {
    "url": "https://example.com/contact",
    "form_selector": "#contact-form",
    "pattern_recognition": {
      "form_type": "contact",
      "confidence": 0.95,
      "patterns_detected": [
        {
          "pattern": "contact_form",
          "confidence": 0.95,
          "fields": [
            {
              "name": "name",
              "type": "text",
              "suggested_mapping": "full_name",
              "confidence": 0.90
            },
            {
              "name": "email",
              "type": "email",
              "suggested_mapping": "email_address",
              "confidence": 0.95
            }
          ]
        }
      ]
    }
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows form pattern recognition
- **Linux**: Complete functionality with Linux form pattern recognition
- **macOS**: Full feature support with macOS form pattern recognition
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Recognize Contact Form
```bash
# Recognize contact form
{
  "url": "https://example.com/contact",
  "form_selector": "#contact-form",
  "timeout": 30000
}

# Result
{
  "success": true,
  "result": {
    "url": "https://example.com/contact",
    "form_selector": "#contact-form",
    "pattern_recognition": {
      "form_type": "contact",
      "confidence": 0.95,
      "patterns_detected": [
        {
          "pattern": "contact_form",
          "confidence": 0.95
        }
      ]
    }
  }
}
```

### Example 2: Map Registration Form
```bash
# Map registration form
{
  "url": "https://example.com/registration",
  "form_selector": "#registration-form",
  "timeout": 30000
}

# Result
{
  "success": true,
  "result": {
    "url": "https://example.com/registration",
    "form_selector": "#registration-form",
    "pattern_recognition": {
      "form_type": "registration",
      "confidence": 0.90,
      "patterns_detected": [
        {
          "pattern": "registration_form",
          "confidence": 0.90,
          "fields": [
            {
              "name": "username",
              "type": "text",
              "suggested_mapping": "username",
              "confidence": 0.95
            },
            {
              "name": "password",
              "type": "password",
              "suggested_mapping": "password",
              "confidence": 0.95
            }
          ]
        }
      ]
    }
  }
}
```

### Example 3: Classify Checkout Form
```bash
# Classify checkout form
{
  "url": "https://example.com/checkout",
  "form_selector": "#checkout-form",
  "timeout": 30000
}

# Result
{
  "success": true,
  "result": {
    "url": "https://example.com/checkout",
    "form_selector": "#checkout-form",
    "pattern_recognition": {
      "form_type": "checkout",
      "confidence": 0.85,
      "patterns_detected": [
        {
          "pattern": "checkout_form",
          "confidence": 0.85,
          "fields": [
            {
              "name": "card_number",
              "type": "text",
              "suggested_mapping": "credit_card_number",
              "confidence": 0.90
            },
            {
              "name": "expiry_date",
              "type": "text",
              "suggested_mapping": "expiry_date",
              "confidence": 0.85
            }
          ]
        }
      ]
    }
  }
}
```

## Error Handling
- **Pattern Errors**: Proper handling of form pattern recognition failures
- **Field Errors**: Secure handling of field mapping failures
- **Classification Errors**: Robust error handling for form classification failures
- **Recognition Errors**: Safe handling of pattern recognition problems

## Related Tools
- **Form Detection**: Form detection and analysis tools
- **Form Completion**: Form completion and automation tools
- **Form Validation**: Form validation and completion tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Form Pattern Recognition Tool, please refer to the main MCP God Mode documentation or contact the development team.
