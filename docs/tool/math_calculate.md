# Mathematical Calculator Tool

## Overview
The `math_calculate` tool provides advanced mathematical calculation capabilities with scientific functions, unit conversions, and complex expressions. This tool supports trigonometry, logarithms, statistics, and more across all platforms.

## Tool Name
`math_calculate`

## Description
Advanced mathematical calculator with scientific functions, unit conversions, and complex expressions

## Input Schema
- `expression` (string, required): The mathematical expression to evaluate. Supports advanced functions: sin, cos, tan, log, ln, sqrt, exp, abs, ceil, floor, round, factorial, etc. Examples: 'sin(Math.PI/4)', 'Math.log10(100)', 'Math.sqrt(25)', '2**8', 'factorial(5)'

- `precision` (number, optional): Number of decimal places to display in the result. Examples: 2 for currency calculations, 5 for scientific work, 10 for high precision. Range: 0-15 decimal places. Default: 10

- `mode` (string, optional): Calculation mode. Options include:
  - `basic` - Basic arithmetic operations
  - `scientific` - Advanced mathematical functions
  - `statistical` - Data analysis and statistics
  - `unit_conversion` - Unit conversions

## Natural Language Access
Users can ask for this tool using natural language such as:
- "Calculate 2 plus 2"
- "What is the square root of 144?"
- "Calculate the sine of 45 degrees"
- "Convert 100 dollars to euros"
- "Calculate the factorial of 10"
- "What is 2 to the power of 8?"
- "Calculate the logarithm of 1000"
- "Convert 5 kilometers to miles"

## Examples

### Basic Arithmetic
```typescript
// Simple addition
const result = await server.callTool("math_calculate", { 
  expression: "2 + 2",
  mode: "basic"
});

// Complex expression
const result = await server.callTool("math_calculate", { 
  expression: "2 * (3 + 4) / 2",
  mode: "basic"
});
```

### Scientific Functions
```typescript
// Trigonometric functions
const result = await server.callTool("math_calculate", { 
  expression: "sin(Math.PI/4)",
  mode: "scientific",
  precision: 5
});

// Logarithmic functions
const result = await server.callTool("math_calculate", { 
  expression: "Math.log10(100)",
  mode: "scientific"
});
```

### Advanced Mathematics
```typescript
// Power calculations
const result = await server.callTool("math_calculate", { 
  expression: "2**8",
  mode: "scientific"
});

// Factorial
const result = await server.callTool("math_calculate", { 
  expression: "factorial(5)",
  mode: "scientific"
});
```

### Unit Conversions
```typescript
// Currency conversion
const result = await server.callTool("math_calculate", { 
  expression: "100 USD to EUR",
  mode: "unit_conversion"
});

// Distance conversion
const result = await server.callTool("math_calculate", { 
  expression: "5 km to miles",
  mode: "unit_conversion"
});
```

## Platform Support
- ✅ Windows
- ✅ Linux
- ✅ macOS
- ✅ Android
- ✅ iOS

## Mathematical Functions Supported

### Basic Operations
- **Addition**: `+`
- **Subtraction**: `-`
- **Multiplication**: `*`
- **Division**: `/`
- **Modulo**: `%`
- **Power**: `**` or `^`
- **Parentheses**: `()` for grouping

### Trigonometric Functions
- **Sine**: `sin(x)`
- **Cosine**: `cos(x)`
- **Tangent**: `tan(x)`
- **Arc Sine**: `asin(x)`
- **Arc Cosine**: `acos(x)`
- **Arc Tangent**: `atan(x)`
- **Hyperbolic Functions**: `sinh(x)`, `cosh(x)`, `tanh(x)`

### Logarithmic Functions
- **Natural Logarithm**: `ln(x)` or `Math.log(x)`
- **Base-10 Logarithm**: `Math.log10(x)`
- **Base-2 Logarithm**: `Math.log2(x)`
- **Exponential**: `exp(x)` or `Math.exp(x)`

### Mathematical Constants
- **Pi**: `Math.PI` or `π`
- **Euler's Number**: `Math.E` or `e`
- **Golden Ratio**: `φ`
- **Infinity**: `Infinity`
- **Not a Number**: `NaN`

### Advanced Functions
- **Square Root**: `sqrt(x)` or `Math.sqrt(x)`
- **Absolute Value**: `abs(x)` or `Math.abs(x)`
- **Ceiling**: `ceil(x)` or `Math.ceil(x)`
- **Floor**: `floor(x)` or `Math.floor(x)`
- **Round**: `round(x)` or `Math.round(x)`
- **Factorial**: `factorial(x)` or `x!`
- **Random**: `Math.random()`

## Unit Conversion Support

### Length
- **Metric**: meters, kilometers, centimeters, millimeters
- **Imperial**: feet, inches, yards, miles
- **Nautical**: nautical miles, fathoms

### Weight/Mass
- **Metric**: grams, kilograms, metric tons
- **Imperial**: ounces, pounds, tons

### Volume
- **Metric**: liters, milliliters, cubic meters
- **Imperial**: gallons, quarts, pints, cups

### Temperature
- **Celsius**: °C
- **Fahrenheit**: °F
- **Kelvin**: K

### Currency
- **Major Currencies**: USD, EUR, GBP, JPY, CAD, AUD
- **Cryptocurrencies**: BTC, ETH, LTC
- **Real-time Exchange Rates**: When available

### Time
- **Seconds, Minutes, Hours, Days**
- **Weeks, Months, Years**
- **Decades, Centuries, Millennia**

## Statistical Functions

### Descriptive Statistics
- **Mean**: Average of values
- **Median**: Middle value
- **Mode**: Most frequent value
- **Standard Deviation**: Measure of variability
- **Variance**: Square of standard deviation

### Data Analysis
- **Sum**: Total of all values
- **Count**: Number of values
- **Minimum**: Smallest value
- **Maximum**: Largest value
- **Range**: Difference between min and max

## Error Handling
- **Syntax Errors**: Invalid mathematical expressions
- **Domain Errors**: Functions with invalid inputs
- **Overflow Errors**: Numbers too large to handle
- **Division by Zero**: Mathematical impossibility
- **Invalid Units**: Unsupported unit conversions

## Performance Features
- **Fast Calculation**: Optimized mathematical operations
- **Memory Efficient**: Minimal memory usage
- **Precision Control**: Configurable decimal places
- **Mode Selection**: Different calculation modes
- **Caching**: Results caching for repeated calculations

## Related Tools
- `calculator` - Basic calculator functions
- `dice_rolling` - Random number generation
- `system_info` - System information
- `file_ops` - File operations

## Use Cases
- **Scientific Calculations**: Research and analysis
- **Engineering**: Design and calculations
- **Financial**: Currency and financial calculations
- **Education**: Learning and teaching mathematics
- **Data Analysis**: Statistical calculations
- **Unit Conversions**: International measurements
- **Programming**: Mathematical algorithms
- **Research**: Academic and scientific work

## Best Practices
- **Validate Inputs**: Ensure expressions are valid
- **Handle Errors**: Implement proper error handling
- **Use Appropriate Precision**: Choose suitable decimal places
- **Consider Performance**: Optimize complex calculations
- **Document Calculations**: Keep track of mathematical operations
- **Test Edge Cases**: Verify boundary conditions
- **Use Constants**: Leverage built-in mathematical constants
- **Format Output**: Present results clearly and consistently

## Security Considerations
- **Input Validation**: Prevent malicious expressions
- **Resource Limits**: Control calculation complexity
- **Memory Protection**: Prevent memory overflow
- **Execution Time**: Limit calculation duration
- **Access Control**: Restrict tool usage as needed
