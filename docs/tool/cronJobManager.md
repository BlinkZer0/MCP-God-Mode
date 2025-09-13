# Cron Job Manager Tool

## Overview
The **Cron Job Manager Tool** is a comprehensive cron job and scheduled task management utility that provides advanced task scheduling, management, and monitoring capabilities. It offers cross-platform support and enterprise-grade cron job management features.

## Features
- **Task Scheduling**: Advanced task scheduling and management
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Task Monitoring**: Real-time task monitoring and status tracking
- **Task Management**: Comprehensive task management and control
- **Scheduling**: Flexible scheduling and timing options
- **Task Execution**: Automated task execution and management

## Usage

### Task Management
```bash
# List cron jobs
{
  "action": "list_jobs"
}

# Create cron job
{
  "action": "create_job",
  "job_name": "backup_database",
  "schedule": "0 2 * * *",
  "command": "backup_db.sh"
}

# Delete cron job
{
  "action": "delete_job",
  "job_name": "backup_database"
}
```

### Task Scheduling
```bash
# Schedule task
{
  "action": "schedule_task",
  "task_name": "cleanup_logs",
  "schedule": "0 0 * * 0",
  "command": "cleanup_logs.sh"
}

# Update schedule
{
  "action": "update_schedule",
  "job_name": "backup_database",
  "new_schedule": "0 3 * * *"
}

# Pause job
{
  "action": "pause_job",
  "job_name": "backup_database"
}
```

### Task Monitoring
```bash
# Monitor jobs
{
  "action": "monitor_jobs"
}

# Get job status
{
  "action": "get_job_status",
  "job_name": "backup_database"
}

# View job history
{
  "action": "view_job_history",
  "job_name": "backup_database"
}
```

## Parameters

### Task Parameters
- **action**: Cron job management action to perform
- **job_name**: Name of the cron job
- **task_name**: Name of the scheduled task
- **schedule**: Cron schedule expression
- **command**: Command to execute

### Scheduling Parameters
- **schedule_type**: Type of schedule (cron, interval, one_time)
- **timezone**: Timezone for scheduling
- **enabled**: Whether the job is enabled

### Monitoring Parameters
- **monitor_duration**: Duration for monitoring operations
- **status_filter**: Filter for job status
- **history_limit**: Limit for job history

## Output Format
```json
{
  "success": true,
  "action": "list_jobs",
  "result": {
    "jobs": [
      {
        "job_name": "backup_database",
        "schedule": "0 2 * * *",
        "command": "backup_db.sh",
        "status": "enabled",
        "last_run": "2025-09-15T02:00:00Z"
      }
    ],
    "total_jobs": 1
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows Task Scheduler
- **Linux**: Complete functionality with Linux cron
- **macOS**: Full feature support with macOS launchd
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: List Jobs
```bash
# List cron jobs
{
  "action": "list_jobs"
}

# Result
{
  "success": true,
  "result": {
    "jobs": [
      {
        "job_name": "backup_database",
        "schedule": "0 2 * * *",
        "command": "backup_db.sh",
        "status": "enabled"
      }
    ],
    "total_jobs": 1
  }
}
```

### Example 2: Create Job
```bash
# Create cron job
{
  "action": "create_job",
  "job_name": "backup_database",
  "schedule": "0 2 * * *",
  "command": "backup_db.sh"
}

# Result
{
  "success": true,
  "result": {
    "job_name": "backup_database",
    "schedule": "0 2 * * *",
    "command": "backup_db.sh",
    "status": "created"
  }
}
```

### Example 3: Monitor Jobs
```bash
# Monitor jobs
{
  "action": "monitor_jobs"
}

# Result
{
  "success": true,
  "result": {
    "jobs_monitored": 1,
    "active_jobs": 1,
    "failed_jobs": 0,
    "next_execution": "2025-09-16T02:00:00Z"
  }
}
```

## Error Handling
- **Schedule Errors**: Proper handling of invalid schedule expressions
- **Command Errors**: Secure handling of command execution failures
- **Permission Errors**: Robust error handling for permission issues
- **System Errors**: Safe handling of system-level errors

## Related Tools
- **Task Management**: Task management and automation tools
- **System Administration**: System administration and management tools
- **Automation**: Automation and orchestration tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Cron Job Manager Tool, please refer to the main MCP God Mode documentation or contact the development team.
