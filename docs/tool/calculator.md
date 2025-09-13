# Calculator Tool

## Overview
The **Calculator Tool** is a comprehensive mathematical calculation utility that provides advanced mathematical operations, scientific computing, and calculation capabilities. It offers cross-platform support and enterprise-grade mathematical computation features.

## Features
- **Basic Operations**: Addition, subtraction, multiplication, division
- **Advanced Operations**: Power, square root, percentage calculations
- **Scientific Computing**: Advanced mathematical functions and operations
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Precision Control**: Configurable decimal precision for calculations
- **Error Handling**: Robust error handling for mathematical operations

## Usage

### Basic Operations
```bash
# Addition
{
  "operation": "add",
  "a": 10,
  "b": 5
}

# Subtraction
{
  "operation": "subtract",
  "a": 10,
  "b": 5
}

# Multiplication
{
  "operation": "multiply",
  "a": 10,
  "b": 5
}

# Division
{
  "operation": "divide",
  "a": 10,
  "b": 5
}
```

### Advanced Operations
```bash
# Power calculation
{
  "operation": "power",
  "a": 2,
  "b": 3
}

# Square root
{
  "operation": "sqrt",
  "a": 16
}

# Percentage
{
  "operation": "percentage",
  "a": 50,
  "b": 200
}
```

### Precision Control
```bash
# High precision calculation
{
  "operation": "divide",
  "a": 22,
  "b": 7,
  "precision": 10
}

# Scientific notation
{
  "operation": "multiply",
  "a": 1.5e6,
  "b": 2.5e3
}
```

## Parameters

### Operation Parameters
- **operation**: Mathematical operation to perform
- **a**: First number for calculation
- **b**: Second number for calculation (not needed for sqrt)
- **precision**: Decimal precision for result

### Operation Types
- **add**: Addition operation
- **subtract**: Subtraction operation
- **multiply**: Multiplication operation
- **divide**: Division operation
- **power**: Power/exponentiation operation
- **sqrt**: Square root operation
- **percentage**: Percentage calculation

## Output Format
```json
{
  "success": true,
  "operation": "add",
  "result": 15,
  "precision": 2,
  "formatted_result": "15.00"
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows mathematical libraries
- **Linux**: Complete functionality with Linux mathematical libraries
- **macOS**: Full feature support with macOS mathematical libraries
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Basic Addition
```bash
# Add numbers
{
  "operation": "add",
  "a": 10,
  "b": 5
}

# Result
{
  "success": true,
  "operation": "add",
  "result": 15,
  "precision": 2,
  "formatted_result": "15.00"
}
```

### Example 2: Power Calculation
```bash
# Calculate power
{
  "operation": "power",
  "a": 2,
  "b": 3
}

# Result
{
  "success": true,
  "operation": "power",
  "result": 8,
  "precision": 2,
  "formatted_result": "8.00"
}
```

### Example 3: Square Root
```bash
# Calculate square root
{
  "operation": "sqrt",
  "a": 16
}

# Result
{
  "success": true,
  "operation": "sqrt",
  "result": 4,
  "precision": 2,
  "formatted_result": "4.00"
}
```

## Error Handling
- **Division by Zero**: Proper handling of division by zero errors
- **Invalid Operations**: Secure handling of invalid mathematical operations
- **Precision Errors**: Robust error handling for precision-related issues
- **Input Validation**: Safe handling of invalid input values

## Related Tools
- **Mathematical Computing**: Advanced mathematical computing tools
- **Scientific Computing**: Scientific computing and analysis tools
- **Data Analysis**: Data analysis and statistical tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Calculator Tool, please refer to the main MCP God Mode documentation or contact the development team.