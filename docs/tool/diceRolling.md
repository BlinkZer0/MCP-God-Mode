# Dice Rolling Tool

## Overview
The **Dice Rolling Tool** is a comprehensive dice rolling simulator utility that provides advanced dice rolling capabilities for tabletop games, RPGs, and gaming applications. It offers cross-platform support and enterprise-grade dice rolling features.

## Features
- **Dice Rolling**: Advanced dice rolling simulation and management
- **Game Support**: Comprehensive support for tabletop games and RPGs
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Multiple Dice Types**: Support for various dice types and configurations
- **Game Mechanics**: Advanced game mechanics and probability calculations
- **Rolling Options**: Multiple rolling options and configurations

## Usage

### Basic Dice Rolling
```bash
# Roll dice
{
  "dice_notation": "2d6"
}

# Roll with advantage
{
  "dice_notation": "1d20",
  "advantage": true
}

# Roll with disadvantage
{
  "dice_notation": "1d20",
  "disadvantage": true
}
```

### Advanced Rolling
```bash
# Roll multiple times
{
  "dice_notation": "3d8+5",
  "count": 3
}

# Roll with modifiers
{
  "dice_notation": "2d6+3",
  "count": 2
}

# Roll complex dice
{
  "dice_notation": "4d6",
  "count": 6
}
```

### Game Mechanics
```bash
# Roll for initiative
{
  "dice_notation": "1d20+5",
  "count": 1
}

# Roll for damage
{
  "dice_notation": "2d8+4",
  "count": 1
}

# Roll for skill check
{
  "dice_notation": "1d20+7",
  "count": 1
}
```

## Parameters

### Dice Parameters
- **dice_notation**: Dice notation (e.g., '2d6', '1d20', '3d8+5')
- **count**: Number of times to roll (default: 1)
- **advantage**: Roll with advantage (take highest of 2 rolls)
- **disadvantage**: Roll with disadvantage (take lowest of 2 rolls)

### Game Parameters
- **game_type**: Type of game (dnd, pathfinder, custom)
- **roll_type**: Type of roll (attack, damage, skill, save)
- **modifier**: Additional modifier to add to rolls

### Rolling Parameters
- **roll_mode**: Rolling mode (normal, advantage, disadvantage)
- **roll_count**: Number of rolls to perform
- **roll_modifier**: Modifier to add to each roll

## Output Format
```json
{
  "success": true,
  "result": {
    "dice_notation": "2d6",
    "rolls": [4, 6],
    "total": 10,
    "roll_count": 1,
    "advantage": false,
    "disadvantage": false
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows dice rolling
- **Linux**: Complete functionality with Linux dice rolling
- **macOS**: Full feature support with macOS dice rolling
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Basic Roll
```bash
# Roll dice
{
  "dice_notation": "2d6"
}

# Result
{
  "success": true,
  "result": {
    "dice_notation": "2d6",
    "rolls": [4, 6],
    "total": 10,
    "roll_count": 1
  }
}
```

### Example 2: Advantage Roll
```bash
# Roll with advantage
{
  "dice_notation": "1d20",
  "advantage": true
}

# Result
{
  "success": true,
  "result": {
    "dice_notation": "1d20",
    "rolls": [15, 18],
    "total": 18,
    "roll_count": 1,
    "advantage": true
  }
}
```

### Example 3: Multiple Rolls
```bash
# Roll multiple times
{
  "dice_notation": "3d8+5",
  "count": 3
}

# Result
{
  "success": true,
  "result": {
    "dice_notation": "3d8+5",
    "rolls": [18, 22, 16],
    "total": 56,
    "roll_count": 3,
    "modifier": 5
  }
}
```

## Error Handling
- **Dice Errors**: Proper handling of invalid dice notation
- **Roll Errors**: Secure handling of dice rolling failures
- **Game Errors**: Robust error handling for game mechanics failures
- **Parameter Errors**: Safe handling of invalid rolling parameters

## Related Tools
- **Game Tools**: Game management and simulation tools
- **Random Number Generation**: Random number generation and simulation tools
- **Probability Tools**: Probability calculation and analysis tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Dice Rolling Tool, please refer to the main MCP God Mode documentation or contact the development team.
