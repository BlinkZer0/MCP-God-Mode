# Autonomous Cascade Tool - Complete Guide

## Overview

The Autonomous Cascade Tool enables agents to plan → act → evaluate → repeat without waiting for new user prompts, until a clear stop condition is met. This powerful system provides a complete autonomous planning and execution framework with advanced natural language processing, safety controls, and resumability.

## Quick Start

### Basic Usage
```bash
# Simple autonomous goal
cascade.auto --goal "Fix all TypeScript errors in my project" --risk write_fs

# Natural language parsing
cascade.parse_natural_language --input "Build a website until done; trust your guidance"

# Interactive goal building
cascade.build_goal_interactive --step goal
```

### Example Scenarios

#### 1. Fix Code Until Done
```json
{
  "tool": "cascade.auto",
  "args": {
    "goal": "Fix all compilation errors in the codebase",
    "risk": "write_fs",
    "max_rounds": 15,
    "hard_budget_seconds": 1800,
    "allowed_tools": ["fs_read_text", "fs_write_text", "proc_run", "grep"],
    "safe_mode": true
  }
}
```

#### 2. Build DSM-5 Wiki
```json
{
  "tool": "cascade.auto",
  "args": {
    "goal": "Build a comprehensive DSM-5 wiki with searchable content",
    "risk": "networked",
    "max_rounds": 30,
    "hard_budget_seconds": 3600,
    "allowed_tools": ["web_search", "fs_write_text", "proc_run", "download_file"],
    "context_hints": "Focus on creating a professional, accessible mental health resource"
  }
}
```

#### 3. Deep Internet Research
```json
{
  "tool": "cascade.auto",
  "args": {
    "goal": "Research the latest developments in quantum computing for 20 minutes",
    "risk": "networked",
    "max_rounds": 15,
    "hard_budget_seconds": 1200,
    "allowed_tools": ["web_search", "web_scraper", "fs_write_text"],
    "artifacts_dir": "./research_output"
  }
}
```

## Available Tools

### Core Tools

#### `cascade.auto`
**Main autonomous execution engine**

**Parameters:**
- `goal` (required): The objective to accomplish
- `context_hints` (optional): Additional context for better planning
- `max_rounds` (optional): Maximum planning rounds (1-100, default: 10)
- `hard_budget_seconds` (optional): Time limit in seconds (30-7200, default: 600)
- `risk` (optional): Risk level - `read_only`, `write_fs`, `networked` (default: read_only)
- `allowed_tools` (optional): List of permitted tools
- `disallowed_tools` (optional): List of forbidden tools
- `artifacts_dir` (optional): Directory for storing outputs
- `safe_mode` (optional): Enable safety protections (default: true)
- `dry_run` (optional): Preview mode without execution (default: false)

**Example:**
```json
{
  "goal": "Optimize database queries in the user service",
  "risk": "write_fs",
  "max_rounds": 20,
  "hard_budget_seconds": 2400,
  "context_hints": "Focus on the most frequently used queries first"
}
```

#### `cascade.parse_goal`
**Basic natural language goal parsing**

**Parameters:**
- `input` (required): Natural language goal description
- `preset` (optional): Use a predefined goal template

**Example:**
```json
{
  "input": "Fix bugs until done; trust your guidance",
  "preset": "fix_bugs"
}
```

#### `cascade.get_presets`
**Retrieve available goal presets**

**Returns:** List of predefined goal configurations for common scenarios.

#### `cascade.resume`
**Resume previous cascade runs**

**Parameters:**
- `plan_id` (required): UUID of the plan to resume

**Example:**
```json
{
  "plan_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Natural Language Interface Tools

#### `cascade.parse_natural_language`
**Advanced NLP parsing with confidence scoring**

**Parameters:**
- `input` (required): Complex natural language request
- `include_suggestions` (optional): Include optimization suggestions (default: true)
- `validate_config` (optional): Validate parsed configuration (default: true)

**Example:**
```json
{
  "input": "Build a responsive portfolio website for 30 minutes using modern frameworks",
  "include_suggestions": true,
  "validate_config": true
}
```

**Response:**
```json
{
  "success": true,
  "result": {
    "parsed_config": {
      "goal": "Build a responsive portfolio website using modern frameworks",
      "hard_budget_seconds": 1800,
      "risk": "write_fs",
      "confidence": 0.85
    },
    "suggestions": [
      "Consider specifying preferred frameworks (React, Vue, Angular)",
      "Add deployment target for complete workflow"
    ],
    "validation": {
      "valid": true,
      "warnings": [],
      "errors": []
    }
  }
}
```

#### `cascade.build_goal_interactive`
**Interactive goal builder with guided questions**

**Parameters:**
- `partial_input` (optional): Starting input
- `step` (optional): Current step - `goal`, `risk`, `time`, `tools`, `safety`, `review`
- `previous_answers` (optional): Answers from previous steps

**Example Flow:**
```json
// Step 1: Goal
{
  "step": "goal"
}
// Response: "What would you like to accomplish?"

// Step 2: Risk Level
{
  "step": "risk",
  "previous_answers": {"goal": "Build a web scraper"}
}
// Response: Risk level options with explanations

// Step 3: Time Budget
{
  "step": "time",
  "previous_answers": {"goal": "Build a web scraper", "risk": "networked"}
}
// Response: Time budget suggestions
```

#### `cascade.match_templates`
**Template matching against predefined patterns**

**Parameters:**
- `input` (required): Input to match against templates
- `return_all_matches` (optional): Return all matches vs top 3 (default: false)

**Example:**
```json
{
  "input": "Debug the authentication system",
  "return_all_matches": false
}
```

**Response:**
```json
{
  "success": true,
  "result": [
    {
      "template": "fix_bugs",
      "score": 2,
      "confidence": 0.8,
      "config": {
        "risk": "write_fs",
        "max_rounds": 15,
        "allowed_tools": ["fs_read_text", "fs_write_text", "proc_run", "grep"]
      }
    }
  ]
}
```

#### `cascade.generate_suggestions`
**Context-aware configuration optimization**

**Parameters:**
- `current_config` (required): Current cascade configuration
- `context` (optional): Additional context
- `focus_area` (optional): Focus area - `performance`, `safety`, `completeness`, `efficiency`

**Example:**
```json
{
  "current_config": {
    "goal": "Analyze large dataset",
    "max_rounds": 50,
    "risk": "networked"
  },
  "focus_area": "performance"
}
```

## Natural Language Shortcuts

The system recognizes common phrases and converts them to structured configurations:

### Time Constraints
- **"for 20 minutes"** → `hard_budget_seconds: 1200`
- **"within 1 hour"** → `hard_budget_seconds: 3600`
- **"for 30 seconds"** → `hard_budget_seconds: 30`

### Autonomy Levels
- **"until done"** → `max_rounds: 20, hard_budget_seconds: 1800, risk: write_fs`
- **"trust your guidance"** → `max_rounds: 20, risk: write_fs`
- **"fully autonomous"** → `max_rounds: 25, risk: write_fs`

### Risk Levels
- **"read-only"** → `risk: read_only, safe_mode: true`
- **"safe mode"** → `safe_mode: true`
- **"networked"** → `risk: networked`
- **"file changes allowed"** → `risk: write_fs`

### Safety Controls
- **"dry-run"** → `dry_run: true`
- **"preview only"** → `dry_run: true`
- **"careful mode"** → `safe_mode: true`

## Goal Templates

Pre-configured templates for common scenarios:

### `build_website`
```json
{
  "risk": "write_fs",
  "max_rounds": 25,
  "hard_budget_seconds": 2400,
  "allowed_tools": ["fs_write_text", "fs_read_text", "web_search", "proc_run"]
}
```

### `fix_bugs`
```json
{
  "risk": "write_fs",
  "max_rounds": 15,
  "hard_budget_seconds": 1800,
  "allowed_tools": ["fs_read_text", "fs_write_text", "proc_run", "grep"]
}
```

### `research_topic`
```json
{
  "risk": "networked",
  "max_rounds": 20,
  "hard_budget_seconds": 1800,
  "allowed_tools": ["web_search", "web_scraper", "fs_write_text", "download_file"]
}
```

### `security_audit`
```json
{
  "risk": "read_only",
  "max_rounds": 30,
  "hard_budget_seconds": 3600,
  "allowed_tools": ["vulnerability_scanner", "fs_read_text", "network_diagnostics"]
}
```

### `data_analysis`
```json
{
  "risk": "write_fs",
  "max_rounds": 25,
  "hard_budget_seconds": 2400,
  "allowed_tools": ["enhanced_data_analysis", "fs_read_text", "fs_write_text", "chart_generator"]
}
```

## Safety & Risk Management

### Risk Levels

#### `read_only` (Safest)
- **Allowed**: File reading, analysis, reporting
- **Blocked**: File writing, command execution, network requests
- **Use Cases**: Analysis, auditing, research without modifications

#### `write_fs` (Moderate Risk)
- **Allowed**: File system operations, local command execution
- **Blocked**: Network requests, external API calls
- **Use Cases**: Code fixes, local development, file processing

#### `networked` (Full Access)
- **Allowed**: All operations including network access
- **Blocked**: Only explicitly disallowed tools
- **Use Cases**: Web scraping, API integration, deployment

### Safety Features

#### Safe Mode (Default: Enabled)
- Blocks destructive operations
- Requires explicit confirmation for risky actions
- Provides warnings for potentially dangerous operations

#### Dry Run Mode
- Previews all planned actions without execution
- Shows what would happen without making changes
- Perfect for testing and validation

#### Tool Restrictions
- **Allow Lists**: Only specified tools can be used
- **Deny Lists**: Specified tools are forbidden
- **Risk-based Filtering**: Automatic tool restriction based on risk level

## Artifacts & Resumability

### Artifact Organization
```
artifacts/
├── {plan_id}/                    # Unique plan identifier
│   ├── round_001/               # First planning round
│   │   ├── checkpoint.json      # Complete state snapshot
│   │   ├── plan.json           # Generated plan
│   │   ├── results.json        # Action results
│   │   └── outputs/            # Generated files
│   ├── round_002/              # Second round
│   │   └── ...
│   ├── final_summary.json      # Complete run summary
│   └── artifacts_index.json    # File index
```

### Checkpoint System
Each round automatically saves:
- **Plan State**: Current plan and progress
- **Action Results**: Success/failure of each action
- **Context**: Accumulated knowledge and decisions
- **Timing**: Elapsed time and remaining budget
- **Artifacts**: Generated files and outputs

### Resume Capability
```json
{
  "tool": "cascade.resume",
  "args": {
    "plan_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

Resuming will:
1. Load the last checkpoint
2. Restore complete state
3. Continue from where it left off
4. Maintain all context and progress

## Error Handling & Recovery

### Automatic Recovery
- **Transient Failures**: Automatic retry with exponential backoff
- **Tool Unavailability**: Intelligent fallback to alternative tools
- **Resource Constraints**: Graceful degradation when limits reached
- **Invalid Plans**: Re-planning with corrected constraints

### Error Types
- **Validation Errors**: Invalid configuration or parameters
- **Execution Errors**: Tool failures or unexpected results
- **Resource Errors**: Time/round budget exceeded
- **Safety Errors**: Blocked operations or policy violations

### Recovery Strategies
- **Retry Logic**: Up to 2 retries for transient failures
- **Alternative Tools**: Fallback to similar functionality
- **Simplified Plans**: Reduce complexity when resources limited
- **User Intervention**: Request guidance when blocked

## Performance Optimization

### Best Practices

#### Goal Definition
- **Be Specific**: Clear, actionable goals get better results
- **Provide Context**: Additional hints improve planning accuracy
- **Set Realistic Budgets**: Match time/rounds to task complexity

#### Tool Selection
- **Use Allow Lists**: Restrict to relevant tools for better performance
- **Avoid Broad Permissions**: Narrow scope improves decision speed
- **Consider Alternatives**: Multiple tools for same function provide flexibility

#### Resource Management
- **Monitor Progress**: Check round/time usage regularly
- **Adjust Budgets**: Increase limits for complex tasks
- **Use Checkpoints**: Resume capability prevents lost work

### Performance Metrics
- **Planning Speed**: Time per round (target: <30 seconds)
- **Success Rate**: Percentage of successful actions (target: >80%)
- **Resource Efficiency**: Budget utilization (target: 70-90%)
- **Goal Achievement**: Completion rate (target: >90%)

## Troubleshooting

### Common Issues

#### "Low Confidence in Parsing"
**Cause**: Ambiguous or unclear goal description
**Solution**: 
- Use more specific language
- Provide additional context hints
- Try interactive goal builder

#### "Budget Exceeded"
**Cause**: Task more complex than estimated
**Solution**:
- Increase time/round budgets
- Break goal into smaller parts
- Use resume capability to continue

#### "Tool Not Allowed"
**Cause**: Required tool blocked by risk level or restrictions
**Solution**:
- Increase risk level if appropriate
- Modify allowed_tools list
- Use alternative tools

#### "Plan Generation Failed"
**Cause**: Conflicting constraints or impossible goal
**Solution**:
- Simplify the goal
- Adjust constraints
- Use template matching for guidance

### Debug Mode
Enable verbose logging by setting `context_hints` to include "debug":
```json
{
  "goal": "Your goal here",
  "context_hints": "debug: enable verbose logging and detailed explanations"
}
```

## Integration Examples

### With Existing Tools
```json
{
  "goal": "Use the multimedia tool to process all images in the uploads folder",
  "risk": "write_fs",
  "allowed_tools": ["multimedia_tool", "fs_list", "fs_read_text"],
  "context_hints": "Focus on image optimization and format conversion"
}
```

### With External APIs
```json
{
  "goal": "Fetch weather data for major cities and create a dashboard",
  "risk": "networked",
  "allowed_tools": ["web_search", "download_file", "fs_write_text", "chart_generator"],
  "context_hints": "Use reliable weather APIs and create responsive HTML dashboard"
}
```

### With Development Workflows
```json
{
  "goal": "Set up CI/CD pipeline for the project",
  "risk": "write_fs",
  "allowed_tools": ["fs_write_text", "proc_run", "git_status"],
  "context_hints": "Use GitHub Actions, include testing and deployment stages"
}
```

## API Reference

### Response Format
All tools return responses in this format:
```json
{
  "success": boolean,
  "result": object | string,
  "error": string | null
}
```

### Error Codes
- `INVALID_GOAL`: Goal is empty or malformed
- `BUDGET_EXCEEDED`: Time or round limit reached
- `TOOL_BLOCKED`: Required tool not allowed
- `PLAN_FAILED`: Unable to generate valid plan
- `EXECUTION_ERROR`: Action execution failed
- `VALIDATION_ERROR`: Configuration validation failed

### Status Codes
- `completed`: Goal successfully achieved
- `blocked`: Waiting for user intervention
- `need_user`: Requires user input to continue
- `budget_exceeded`: Time or round limit reached
- `error`: Unrecoverable error occurred

## Best Practices

### Security
- **Start with Safe Mode**: Always begin with safety protections enabled
- **Use Appropriate Risk Levels**: Match risk to actual requirements
- **Review Generated Plans**: Check plans before execution in critical environments
- **Monitor Resource Usage**: Watch for unusual patterns or excessive consumption

### Efficiency
- **Provide Good Context**: Detailed context hints improve planning quality
- **Use Templates**: Leverage predefined templates for common scenarios
- **Set Realistic Budgets**: Match time/round limits to task complexity
- **Monitor Progress**: Check status regularly and adjust as needed

### Reliability
- **Enable Checkpoints**: Use artifact system for resumability
- **Plan for Failures**: Include error handling in your workflow
- **Test with Dry Runs**: Validate plans before execution
- **Keep Backups**: Preserve important data before autonomous operations

## Support & Community

### Getting Help
- **Documentation**: Comprehensive guides and examples
- **Error Messages**: Detailed error descriptions with suggested solutions
- **Debug Mode**: Verbose logging for troubleshooting
- **Community**: Share experiences and solutions

### Contributing
- **Report Issues**: Help improve the system by reporting bugs
- **Suggest Features**: Propose new capabilities or improvements
- **Share Templates**: Contribute goal templates for common scenarios
- **Improve Documentation**: Help make guides clearer and more complete

---

The Autonomous Cascade Tool represents a significant advancement in autonomous agent capabilities, providing a robust, safe, and flexible foundation for complex automated tasks. With its comprehensive natural language processing, advanced safety controls, and powerful resumability features, it enables unprecedented levels of autonomous operation while maintaining the safety and reliability required for production use.
