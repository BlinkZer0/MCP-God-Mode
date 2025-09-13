# Types Tool

## Overview
The **Types Tool** is a comprehensive type system utility that provides type definitions, validation, and management capabilities. It offers cross-platform support and advanced type handling features.

## Features
- **Type Definitions**: Comprehensive type definition management
- **Type Validation**: Advanced type validation and checking
- **Type Conversion**: Type conversion and transformation
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Type Safety**: Type safety enforcement and validation
- **Type Inference**: Automatic type inference and detection

## Usage

### Type Definitions
```bash
# Define type
{
  "action": "define_type",
  "type_name": "User",
  "type_definition": {
    "id": "number",
    "name": "string",
    "email": "string",
    "active": "boolean"
  }
}

# Define complex type
{
  "action": "define_type",
  "type_name": "ApiResponse",
  "type_definition": {
    "success": "boolean",
    "data": "any",
    "error": "string",
    "timestamp": "Date"
  }
}
```

### Type Validation
```bash
# Validate type
{
  "action": "validate_type",
  "type_name": "User",
  "data": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "active": true
  }
}

# Validate with strict mode
{
  "action": "validate_type",
  "type_name": "User",
  "data": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "active": true
  },
  "strict": true
}
```

### Type Conversion
```bash
# Convert type
{
  "action": "convert_type",
  "source_type": "string",
  "target_type": "number",
  "value": "123"
}

# Convert with validation
{
  "action": "convert_type",
  "source_type": "string",
  "target_type": "number",
  "value": "123",
  "validate": true
}
```

### Type Inference
```bash
# Infer type
{
  "action": "infer_type",
  "data": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "active": true
  }
}

# Infer with options
{
  "action": "infer_type",
  "data": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "active": true
  },
  "options": {
    "strict": true,
    "nullable": false
  }
}
```

### Type Management
```bash
# List types
{
  "action": "list_types"
}

# Get type info
{
  "action": "get_type_info",
  "type_name": "User"
}

# Update type
{
  "action": "update_type",
  "type_name": "User",
  "updates": {
    "id": "string",
    "name": "string",
    "email": "string",
    "active": "boolean",
    "created_at": "Date"
  }
}

# Delete type
{
  "action": "delete_type",
  "type_name": "User"
}
```

## Parameters

### Type Parameters
- **action**: Type operation to perform
- **type_name**: Name of the type
- **type_definition**: Type definition object
- **data**: Data to validate or convert

### Validation Parameters
- **strict**: Use strict validation mode
- **validate**: Enable validation during conversion
- **options**: Additional validation options

### Conversion Parameters
- **source_type**: Source type for conversion
- **target_type**: Target type for conversion
- **value**: Value to convert

## Output Format
```json
{
  "success": true,
  "action": "define_type",
  "result": {
    "type_name": "User",
    "type_definition": {
      "id": "number",
      "name": "string",
      "email": "string",
      "active": "boolean"
    },
    "status": "defined",
    "created_at": "2025-01-15T10:30:00Z"
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows-specific features
- **Linux**: Complete functionality with Linux-specific details
- **macOS**: Full feature support with macOS integration
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Type Definition
```bash
# Define type
{
  "action": "define_type",
  "type_name": "User",
  "type_definition": {
    "id": "number",
    "name": "string",
    "email": "string",
    "active": "boolean"
  }
}

# Result
{
  "success": true,
  "result": {
    "type_name": "User",
    "status": "defined",
    "created_at": "2025-01-15T10:30:00Z"
  }
}
```

### Example 2: Type Validation
```bash
# Validate type
{
  "action": "validate_type",
  "type_name": "User",
  "data": {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com",
    "active": true
  }
}

# Result
{
  "success": true,
  "result": {
    "type_name": "User",
    "valid": true,
    "errors": []
  }
}
```

### Example 3: Type Conversion
```bash
# Convert type
{
  "action": "convert_type",
  "source_type": "string",
  "target_type": "number",
  "value": "123"
}

# Result
{
  "success": true,
  "result": {
    "source_type": "string",
    "target_type": "number",
    "value": "123",
    "converted_value": 123,
    "conversion_successful": true
  }
}
```

## Error Handling
- **Type Errors**: Proper handling of type definition and validation issues
- **Conversion Errors**: Secure handling of type conversion failures
- **Validation Errors**: Robust error handling for validation problems
- **Inference Errors**: Safe handling of type inference failures

## Related Tools
- **Data Processing**: Data processing tools
- **Validation**: Data validation tools
- **Conversion**: Data conversion tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Types Tool, please refer to the main MCP God Mode documentation or contact the development team.
