# Enhanced Calculator Tool

## Overview
The Enhanced Calculator tool (`mcp_mcp-god-mode_enhanced_calculator`) is a comprehensive mathematical computation tool that combines basic arithmetic operations with advanced mathematical expressions and scientific functions.

## Consolidation
This tool consolidates the functionality of:
- `calculator` - Basic mathematical calculator with standard operations
- `math_calculate` - Advanced mathematical calculations and scientific computing

## Features

### Basic Mode
- **Arithmetic Operations**: add, subtract, multiply, divide
- **Advanced Operations**: power, square root, percentage, factorial
- **Mathematical Functions**: absolute value, rounding (round, floor, ceil)

### Advanced Mode
- **Expression Evaluation**: Complex mathematical expressions with variables
- **Scientific Functions**: Trigonometric (sin, cos, tan, asin, acos, atan), Hyperbolic (sinh, cosh, tanh)
- **Logarithmic Functions**: log, ln, exponential (exp)
- **Number Theory**: GCD, LCM

### Expression Mode
- **Variable Support**: Use variables in mathematical expressions
- **Function Support**: Built-in mathematical functions
- **Precision Control**: Configurable decimal precision (0-15 digits)

## Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `mode` | string | Calculation mode: "basic", "advanced", "expression" | "basic" |
| `operation` | string | Mathematical operation (for basic mode) | - |
| `a` | number | First number for calculation | - |
| `b` | number | Second number for calculation | - |
| `expression` | string | Mathematical expression to evaluate | - |
| `variables` | object | Variables to substitute in expression | - |
| `precision` | number | Decimal precision (0-15) | - |
| `format` | string | Output format: "decimal", "fraction", "scientific", "engineering" | "decimal" |
| `function_name` | string | Advanced mathematical function to apply | - |
| `angle_unit` | string | Angle unit: "degrees", "radians" | "radians" |

## Usage Examples

### Basic Arithmetic
```json
{
  "mode": "basic",
  "operation": "add",
  "a": 5,
  "b": 3
}
```

### Advanced Expression
```json
{
  "mode": "expression",
  "expression": "sin(x) + cos(y)",
  "variables": {
    "x": 1.57,
    "y": 0.785
  },
  "precision": 4
}
```

### Scientific Function
```json
{
  "mode": "advanced",
  "function_name": "log",
  "a": 100,
  "precision": 6
}
```

## Output Format
The tool returns structured results with:
- **Result**: The calculated value
- **Mode**: The calculation mode used
- **Parameters**: Input parameters used
- **Metadata**: Additional information about the calculation

## Cross-Platform Support
- ✅ Windows (including ARM64)
- ✅ macOS (Intel and Apple Silicon)
- ✅ Linux (x86_64 and ARM)
- ✅ Android
- ✅ iOS

## Dependencies
- **mathjs**: Advanced mathematical expression parsing and evaluation
- **Native JavaScript**: Basic arithmetic operations

## Error Handling
- Invalid expressions return detailed error messages
- Division by zero is handled gracefully
- Out-of-range values are validated and reported
- Precision limits are enforced

## Performance
- Basic operations: < 1ms
- Complex expressions: < 10ms
- Large precision calculations: < 100ms

## Security
- Expression evaluation is sandboxed
- No external API calls
- Input validation prevents injection attacks
- Memory usage is bounded
