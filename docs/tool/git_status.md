# Git Status Tool

## Overview
The **Git Status Tool** is a comprehensive Git repository management and status monitoring system that provides detailed information about Git repositories across all platforms (Windows, Linux, macOS, Android, and iOS). This tool offers repository status, branch information, commit history, and change tracking capabilities.

## Features
- **Cross-Platform Support**: Works on Windows, Linux, macOS, Android, and iOS
- **Repository Status**: Check repository status and working directory state
- **Branch Information**: View current branch and available branches
- **Commit History**: Access recent commits and commit details
- **Change Tracking**: Monitor staged, unstaged, and untracked files
- **Remote Integration**: Check remote repository connections
- **Conflict Detection**: Identify merge conflicts and resolution status
- **Performance Monitoring**: Track repository performance metrics

## Supported Git Operations

### Repository Status
- **Working Directory**: Check for uncommitted changes
- **Staging Area**: Monitor staged files and changes
- **Branch Status**: Current branch and tracking information
- **Remote Status**: Connection to remote repositories

### File Status
- **Modified Files**: Track changed files in working directory
- **Staged Files**: Monitor files ready for commit
- **Untracked Files**: Identify new files not in version control
- **Deleted Files**: Track removed files and directories

### Branch Management
- **Current Branch**: Active branch information
- **Branch List**: All available local and remote branches
- **Branch Tracking**: Upstream branch relationships
- **Branch Comparison**: Differences between branches

## Usage Examples

### Basic Repository Status
```typescript
// Check repository status
const status = await gitStatus({
  dir: "./my-project",
  include_untracked: true,
  include_ignored: false
});
```

### Detailed Status with History
```typescript
// Get comprehensive repository information
const info = await gitStatus({
  dir: "./my-project",
  include_untracked: true,
  include_ignored: true,
  include_history: true,
  max_commits: 10
});
```

### Remote Repository Status
```typescript
// Check remote repository connections
const remote = await gitStatus({
  dir: "./my-project",
  check_remote: true,
  include_fetch: true
});
```

## Parameters

### Required Parameters
- **dir**: Directory containing the Git repository

### Optional Parameters
- **include_untracked**: Whether to include untracked files (default: true)
- **include_ignored**: Whether to include ignored files (default: false)
- **include_history**: Whether to include commit history (default: false)
- **max_commits**: Maximum number of commits to include in history (default: 10)
- **check_remote**: Whether to check remote repository status (default: false)
- **include_fetch**: Whether to fetch latest remote information (default: false)

## Return Data Structure

The tool returns a comprehensive Git status object with the following structure:

```typescript
interface GitStatus {
  // Repository information
  repository: RepositoryInfo;
  
  // Current status
  status: StatusInfo;
  
  // Branch information
  branch: BranchInfo;
  
  // File status
  files: FileStatus[];
  
  // Commit history (if requested)
  history?: CommitInfo[];
  
  // Remote information (if requested)
  remote?: RemoteInfo[];
  
  // Summary
  summary: string;
}

interface RepositoryInfo {
  path: string;
  is_git: boolean;
  git_dir: string;
  work_tree: string;
  bare: boolean;
}

interface StatusInfo {
  clean: boolean;
  ahead: number;
  behind: number;
  staged: number;
  modified: number;
  untracked: number;
  conflicts: number;
}

interface BranchInfo {
  current: string;
  tracking?: string;
  ahead: number;
  behind: number;
  branches: string[];
}

interface FileStatus {
  path: string;
  status: string;
  staged: boolean;
  modified: boolean;
  untracked: boolean;
  deleted: boolean;
  renamed?: string;
}

interface CommitInfo {
  hash: string;
  author: string;
  date: string;
  message: string;
  files: string[];
}

interface RemoteInfo {
  name: string;
  url: string;
  fetch: string;
  push: string;
  last_fetch?: string;
}
```

## Git Status Codes

### File Status Indicators
- **M**: Modified file
- **A**: Added file
- **D**: Deleted file
- **R**: Renamed file
- **C**: Copied file
- **U**: Unmerged file (conflict)
- **?**: Untracked file
- **!**: Ignored file

### Working Directory States
- **clean**: No uncommitted changes
- **dirty**: Has uncommitted changes
- **conflicted**: Has merge conflicts
- **ahead**: Local commits ahead of remote
- **behind**: Local commits behind remote

## Advanced Features

### Repository Analysis
- **Size Analysis**: Monitor repository size and growth
- **Performance Metrics**: Track Git operation performance
- **Dependency Analysis**: Analyze repository dependencies
- **Security Scanning**: Check for sensitive information

### Change Tracking
- **Diff Generation**: Generate file difference reports
- **Change Statistics**: Track change patterns over time
- **Author Analysis**: Monitor contributor activity
- **File History**: Track file modification history

### Automation Support
- **Hook Integration**: Integrate with Git hooks
- **CI/CD Support**: Support for continuous integration
- **Scheduled Checks**: Automated status monitoring
- **Alert System**: Notifications for important changes

## Platform-Specific Considerations

### Windows
- **Git for Windows**: Native Windows Git installation
- **PowerShell Integration**: PowerShell Git cmdlets
- **Registry Access**: Windows registry for Git configuration
- **Performance**: Windows-specific optimizations

### Linux/macOS
- **Native Git**: System-installed Git binaries
- **Shell Integration**: Bash/Zsh Git integration
- **Package Management**: apt, yum, brew for Git updates
- **Performance**: Unix-specific optimizations

### Mobile (Android/iOS)
- **Git Apps**: Mobile Git applications
- **Cloud Integration**: Cloud-based Git services
- **Touch Interface**: Mobile-optimized interface
- **Performance**: Battery and memory optimization

## Error Handling

### Common Error Scenarios
1. **Not a Git Repository**
   - Directory not initialized as Git repository
   - Missing .git directory
   - Corrupted Git metadata

2. **Permission Denied**
   - Insufficient file permissions
   - Read-only file system
   - Security restrictions

3. **Git Command Failure**
   - Git not installed
   - Corrupted Git installation
   - Version compatibility issues

4. **Network Issues**
   - Remote repository unavailable
   - Authentication failures
   - Network connectivity problems

### Error Response Format
```typescript
{
  success: false,
  error: "Error description",
  details: "Additional error information",
  recommendations: "Suggested solutions"
}
```

## Best Practices

### Repository Management
- **Regular Status Checks**: Monitor repository state regularly
- **Clean Working Directory**: Keep working directory clean
- **Meaningful Commits**: Create descriptive commit messages
- **Branch Strategy**: Use consistent branching strategies

### Performance Optimization
- **Efficient Scanning**: Use appropriate include/exclude options
- **Caching**: Cache repository information when possible
- **Batch Operations**: Perform operations in batches
- **Resource Monitoring**: Monitor system resources

### Security Considerations
- **Credential Protection**: Secure Git credentials
- **Access Control**: Restrict repository access
- **Audit Logging**: Log repository operations
- **Sensitive Data**: Avoid committing sensitive information

## Troubleshooting

### Common Issues
1. **"Not a Git repository"**
   - Verify directory contains .git folder
   - Check if Git is initialized
   - Ensure correct directory path

2. **"Permission denied"**
   - Check file permissions
   - Verify user access rights
   - Run with appropriate privileges

3. **"Git command failed"**
   - Verify Git installation
   - Check Git version compatibility
   - Reinstall Git if necessary

4. **"Remote connection failed"**
   - Check network connectivity
   - Verify remote URL
   - Check authentication credentials

### Debug Information
Enable debug mode for detailed Git information:
```typescript
// Enable debug logging
process.env.DEBUG = "git:status:*";
```

## Related Tools
- **File Operations Tool**: File system management
- **Process Run Tool**: Execute Git commands
- **System Info Tool**: System information
- **Network Diagnostics Tool**: Network connectivity testing

## Compliance and Legal Considerations

### Data Protection
- **Repository Privacy**: Protect private repository information
- **Access Control**: Restrict repository access
- **Audit Trails**: Maintain operation logs
- **Data Retention**: Implement retention policies

### Corporate Policies
- **Git Usage**: Follow company Git policies
- **Repository Standards**: Use approved repository structures
- **Security Standards**: Meet corporate security requirements
- **Training Requirements**: Ensure proper Git training

## Future Enhancements
- **AI-Powered Analysis**: Machine learning for repository insights
- **Advanced Analytics**: Repository performance analytics
- **Integration**: Third-party service integrations
- **Automation**: Automated repository management
- **Collaboration**: Team-based repository management

---

*This tool is designed for legitimate Git repository management and monitoring purposes. Always ensure compliance with applicable laws and company policies when accessing Git repositories.*
