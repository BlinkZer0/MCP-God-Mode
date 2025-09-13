# Form Validation Tool

## Overview
The **Form Validation Tool** is a comprehensive form validation and data validation utility that provides advanced form data validation, field validation, and business rule validation capabilities. It offers cross-platform support and enterprise-grade form validation features.

## Features
- **Form Validation**: Advanced form data validation and processing
- **Field Validation**: Comprehensive form field validation and analysis
- **Business Rules**: Advanced business rule validation and processing
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Custom Validation**: Custom validation rules and processing
- **Validation Reporting**: Detailed validation reporting and analysis

## Usage

### Form Validation
```bash
# Validate form data
{
  "form_data": {
    "name": "John Doe",
    "email": "john@example.com",
    "age": "25",
    "phone": "+1234567890"
  },
  "validation_rules": {
    "name": {
      "required": true,
      "type": "string",
      "min_length": 2,
      "max_length": 50
    },
    "email": {
      "required": true,
      "type": "email",
      "pattern": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    },
    "age": {
      "required": true,
      "type": "number",
      "min": 18,
      "max": 100
    },
    "phone": {
      "required": true,
      "type": "string",
      "pattern": "^\\+[1-9]\\d{1,14}$"
    }
  }
}

# Validate with strict mode
{
  "form_data": {
    "name": "John Doe",
    "email": "john@example.com",
    "age": "25"
  },
  "validation_rules": {
    "name": {
      "required": true,
      "type": "string"
    },
    "email": {
      "required": true,
      "type": "email"
    },
    "age": {
      "required": true,
      "type": "number"
    }
  },
  "strict_mode": true
}
```

### Field Validation
```bash
# Validate specific fields
{
  "form_data": {
    "email": "john@example.com",
    "password": "SecurePass123!"
  },
  "validation_rules": {
    "email": {
      "required": true,
      "type": "email",
      "custom_validation": "check_domain_whitelist"
    },
    "password": {
      "required": true,
      "type": "string",
      "min_length": 8,
      "pattern": "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]"
    }
  }
}

# Validate with custom rules
{
  "form_data": {
    "username": "john_doe",
    "email": "john@example.com"
  },
  "validation_rules": {
    "username": {
      "required": true,
      "type": "string",
      "min_length": 3,
      "max_length": 20,
      "pattern": "^[a-zA-Z0-9_]+$",
      "custom_validation": "check_username_availability"
    },
    "email": {
      "required": true,
      "type": "email",
      "custom_validation": "check_email_availability"
    }
  }
}
```

### Business Rule Validation
```bash
# Validate business rules
{
  "form_data": {
    "order_amount": "100.50",
    "payment_method": "credit_card",
    "shipping_address": "123 Main St"
  },
  "validation_rules": {
    "order_amount": {
      "required": true,
      "type": "number",
      "min": 0.01,
      "max": 10000.00
    },
    "payment_method": {
      "required": true,
      "type": "string",
      "enum": ["credit_card", "debit_card", "paypal", "bank_transfer"]
    },
    "shipping_address": {
      "required": true,
      "type": "string",
      "min_length": 10,
      "max_length": 200
    }
  }
}
```

## Parameters

### Validation Parameters
- **form_data**: Form data to validate
- **validation_rules**: Custom validation rules for specific fields
- **strict_mode**: Whether to use strict validation mode

### Field Parameters
- **required**: Whether the field is required
- **type**: Field type (string, number, email, date, etc.)
- **pattern**: Regex pattern for validation
- **min_length**: Minimum length for string fields
- **max_length**: Maximum length for string fields
- **min**: Minimum value for number fields
- **max**: Maximum value for number fields

### Custom Validation Parameters
- **custom_validation**: Custom validation function name
- **validation_message**: Custom validation message
- **validation_options**: Additional validation options

## Output Format
```json
{
  "success": true,
  "result": {
    "form_data": {
      "name": "John Doe",
      "email": "john@example.com",
      "age": "25"
    },
    "validation_status": "valid",
    "validation_results": {
      "name": {
        "valid": true,
        "message": "Field is valid"
      },
      "email": {
        "valid": true,
        "message": "Field is valid"
      },
      "age": {
        "valid": true,
        "message": "Field is valid"
      }
    },
    "overall_valid": true
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows form validation
- **Linux**: Complete functionality with Linux form validation
- **macOS**: Full feature support with macOS form validation
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Basic Validation
```bash
# Validate form data
{
  "form_data": {
    "name": "John Doe",
    "email": "john@example.com",
    "age": "25"
  },
  "validation_rules": {
    "name": {
      "required": true,
      "type": "string"
    },
    "email": {
      "required": true,
      "type": "email"
    },
    "age": {
      "required": true,
      "type": "number"
    }
  }
}

# Result
{
  "success": true,
  "result": {
    "form_data": {
      "name": "John Doe",
      "email": "john@example.com",
      "age": "25"
    },
    "validation_status": "valid",
    "overall_valid": true
  }
}
```

### Example 2: Validation with Errors
```bash
# Validate form data with errors
{
  "form_data": {
    "name": "",
    "email": "invalid-email",
    "age": "invalid-age"
  },
  "validation_rules": {
    "name": {
      "required": true,
      "type": "string"
    },
    "email": {
      "required": true,
      "type": "email"
    },
    "age": {
      "required": true,
      "type": "number"
    }
  }
}

# Result
{
  "success": true,
  "result": {
    "form_data": {
      "name": "",
      "email": "invalid-email",
      "age": "invalid-age"
    },
    "validation_status": "invalid",
    "validation_results": {
      "name": {
        "valid": false,
        "message": "Field is required"
      },
      "email": {
        "valid": false,
        "message": "Invalid email format"
      },
      "age": {
        "valid": false,
        "message": "Invalid number format"
      }
    },
    "overall_valid": false
  }
}
```

### Example 3: Custom Validation
```bash
# Validate with custom rules
{
  "form_data": {
    "username": "john_doe",
    "email": "john@example.com"
  },
  "validation_rules": {
    "username": {
      "required": true,
      "type": "string",
      "min_length": 3,
      "max_length": 20,
      "pattern": "^[a-zA-Z0-9_]+$"
    },
    "email": {
      "required": true,
      "type": "email"
    }
  }
}

# Result
{
  "success": true,
  "result": {
    "form_data": {
      "username": "john_doe",
      "email": "john@example.com"
    },
    "validation_status": "valid",
    "validation_results": {
      "username": {
        "valid": true,
        "message": "Field is valid"
      },
      "email": {
        "valid": true,
        "message": "Field is valid"
      }
    },
    "overall_valid": true
  }
}
```

## Error Handling
- **Validation Errors**: Proper handling of form validation failures
- **Field Errors**: Secure handling of field validation failures
- **Rule Errors**: Robust error handling for validation rule failures
- **Data Errors**: Safe handling of invalid form data

## Related Tools
- **Form Detection**: Form detection and analysis tools
- **Form Completion**: Form completion and automation tools
- **Form Processing**: Form processing and validation tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Form Validation Tool, please refer to the main MCP God Mode documentation or contact the development team.
