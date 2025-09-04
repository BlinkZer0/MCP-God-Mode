#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');

async function addBasicTools() {
  try {
    console.log('🔧 Adding basic working tools...');
    
    // Read the current server-refactored.ts file
    const serverFile = path.join(__dirname, 'src', 'server-refactored.ts');
    let serverContent = await fs.readFile(serverFile, 'utf8');
    
    // Find where to insert tools (before helper functions)
    const helperStart = serverContent.indexOf('// ===========================================');
    const helperSection = serverContent.indexOf('// HELPER FUNCTIONS');
    
    if (helperStart === -1 || helperSection === -1) {
      throw new Error('Could not find helper functions section');
    }
    
    // Add basic working tools
    const basicTools = `

// ===========================================
// ADDITIONAL BASIC TOOLS
// ===========================================

// File search tool
server.registerTool("fs_search", {
  description: "Search for files by name pattern",
  inputSchema: {
    pattern: z.string().describe("The file name pattern to search for. Supports glob patterns and partial matches. Examples: '*.txt', 'config*', '*.js', 'README*', '*.{json,yaml}'."),
    dir: z.string().optional().default(".").describe("The directory to search in. Examples: '.', './src', '/home/user/documents', 'C:\\\\Users\\\\User\\\\Projects'. Use '.' for current directory."),
  },
  outputSchema: {
    files: z.array(z.string()).describe("Array of found file paths matching the pattern"),
    count: z.number().describe("Number of files found"),
    pattern: z.string().describe("The search pattern used"),
    directory: z.string().describe("The directory that was searched"),
  }
}, async ({ pattern, dir: searchDir }) => {
  try {
    const resolvedDir = path.resolve(searchDir);
    const safeDir = ensureInsideRoot(resolvedDir);

    // Simple pattern matching implementation
    const files: string[] = [];
    
    // Use arrow function expression instead of function declaration
    const searchDirectory = async (currentDir: string): Promise<void> => {
      try {
        const entries = await fs.readdir(currentDir, { withFileTypes: true });
        
        for (const entry of entries) {
          const fullPath = path.join(currentDir, entry.name);
          
          if (entry.isDirectory()) {
            // Recursively search subdirectories
            await searchDirectory(fullPath);
          } else if (entry.isFile()) {
            // Check if file matches pattern
            if (matchesPattern(entry.name, pattern)) {
              files.push(fullPath);
            }
          }
        }
      } catch (error) {
        // Skip directories we can't access
        console.warn(\`Cannot access directory: \${currentDir}\`);
      }
    };

    await searchDirectory(safeDir);

    return {
      content: [{ type: "text", text: \`Found \${files.length} files matching pattern '\${pattern}'\` }],
      structuredContent: {
        files,
        count: files.length,
        pattern,
        directory: safeDir
      }
    };
  } catch (error) {
    return {
      content: [{ type: "text", text: \`Failed to search files: \${error instanceof Error ? error.message : 'Unknown error'}\` }],
      structuredContent: {
        files: [],
        count: 0,
        pattern,
        directory: searchDir,
        error: error instanceof Error ? error.message : 'Unknown error'
      }
    };
  }
});

// Simple pattern matching function
function matchesPattern(filename: string, pattern: string): boolean {
  // Convert glob pattern to regex
  const regexPattern = pattern
    .replace(/\\./g, '\\\\.')
    .replace(/\\*/g, '.*')
    .replace(/\\?/g, '.')
    .replace(/\\{([^}]+)\\}/g, '($1)')
    .replace(/,/g, '|');
  
  const regex = new RegExp(\`^\${regexPattern}$\`, 'i');
  return regex.test(filename);
}

// File operations tool
server.registerTool("file_ops", {
  description: "File operations: copy, move, delete, create directories",
  inputSchema: {
    operation: z.enum(["copy", "move", "delete", "mkdir", "rmdir"]).describe("The file operation to perform"),
    source: z.string().optional().describe("Source file/directory path"),
    destination: z.string().optional().describe("Destination file/directory path"),
    recursive: z.boolean().default(false).describe("Whether to perform operation recursively for directories")
  },
  outputSchema: {
    success: z.boolean(),
    message: z.string(),
    operation: z.string()
  }
}, async ({ operation, source, destination, recursive }) => {
  try {
    switch (operation) {
      case "copy":
        if (!source || !destination) throw new Error("Source and destination required for copy");
        const sourcePath = ensureInsideRoot(path.resolve(source));
        const destPath = ensureInsideRoot(path.resolve(destination));
        
        if (recursive) {
          await copyDirectoryRecursive(sourcePath, destPath);
        } else {
          await fs.copyFile(sourcePath, destPath);
        }
        return { content: [], structuredContent: { success: true, message: \`Copied \${source} to \${destination}\`, operation } };
        
      case "move":
        if (!source || !destination) throw new Error("Source and destination required for move");
        const moveSource = ensureInsideRoot(path.resolve(source));
        const moveDest = ensureInsideRoot(path.resolve(destination));
        await fs.rename(moveSource, moveDest);
        return { content: [], structuredContent: { success: true, message: \`Moved \${source} to \${destination}\`, operation } };
        
      case "delete":
        if (!source) throw new Error("Source required for delete");
        const deletePath = ensureInsideRoot(path.resolve(source));
        if (recursive) {
          await deleteDirectoryRecursive(deletePath);
        } else {
          await fs.unlink(deletePath);
        }
        return { content: [], structuredContent: { success: true, message: \`Deleted \${source}\`, operation } };
        
      case "mkdir":
        if (!destination) throw new Error("Destination required for mkdir");
        const mkdirPath = ensureInsideRoot(path.resolve(destination));
        await fs.mkdir(mkdirPath, { recursive });
        return { content: [], structuredContent: { success: true, message: \`Created directory \${destination}\`, operation } };
        
      case "rmdir":
        if (!source) throw new Error("Source required for rmdir");
        const rmdirPath = ensureInsideRoot(path.resolve(source));
        await fs.rmdir(rmdirPath);
        return { content: [], structuredContent: { success: true, message: \`Removed directory \${source}\`, operation } };
        
      default:
        throw new Error(\`Unknown operation: \${operation}\`);
    }
  } catch (error) {
    return { 
      content: [], 
      structuredContent: { 
        success: false, 
        message: \`Operation failed: \${error instanceof Error ? error.message : 'Unknown error'}\`, 
        operation 
      } 
    };
  }
});

// Process run tool
server.registerTool("proc_run", {
  description: "Run a process and return stdout/stderr",
  inputSchema: { 
    command: z.string().describe("The command to execute. Examples: 'ls', 'dir', 'echo hello', 'git status'"), 
    args: z.array(z.string()).default([]).describe("Array of command-line arguments to pass to the command. Examples: ['-la'] for 'ls -la', ['status'] for 'git status'."),
    cwd: z.string().optional().describe("The working directory where the command will be executed. Examples: './project', '/home/user/documents', 'C:\\\\Users\\\\User\\\\Desktop'. Leave empty to use the current working directory."),
    timeout: z.number().default(30000).describe("Timeout in milliseconds for the command execution. Examples: 5000 for 5 seconds, 60000 for 1 minute.")
  },
  outputSchema: { 
    success: z.boolean(), 
    stdout: z.string().optional(), 
    stderr: z.string().optional(),
    exitCode: z.number().optional(),
    command: z.string(),
    cwd: z.string()
  }
}, async ({ command, args, cwd, timeout }) => {
  try {
    // Security check
    if (shouldPerformSecurityChecks() && isDangerousCommand(command)) {
      throw new Error(\`Command blocked for security reasons: \${command}\`);
    }
    
    // Sanitize command
    const { command: sanitizedCommand, args: sanitizedArgs } = sanitizeCommand(command, args);
    
    // Set working directory
    const workingDir = cwd ? ensureInsideRoot(path.resolve(cwd)) : process.cwd();
    
    // Execute command
    const { stdout, stderr } = await execAsync(\`\${sanitizedCommand} \${sanitizedArgs.join(" ")}\`, { 
      cwd: workingDir,
      timeout 
    });
    
    return { 
      content: [], 
      structuredContent: { 
        success: true, 
        stdout: stdout || undefined, 
        stderr: stderr || undefined,
        exitCode: 0,
        command: \`\${sanitizedCommand} \${sanitizedArgs.join(" ")}\`,
        cwd: workingDir
      } 
    };
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return { 
      content: [], 
      structuredContent: { 
        success: false, 
        stdout: undefined, 
        stderr: errorMessage,
        exitCode: -1,
        command: \`\${command} \${args.join(" ")}\`,
        cwd: cwd || process.cwd()
      } 
    };
  }
});

`;

    // Insert the tools content before helper functions
    const beforeHelper = serverContent.substring(0, helperStart);
    const afterHelper = serverContent.substring(helperStart);
    
    const newContent = beforeHelper + basicTools + afterHelper;
    
    // Write the updated file
    await fs.writeFile(serverFile, newContent, 'utf8');
    
    console.log('✅ Successfully added basic tools to server-refactored.ts');
    console.log(`📊 Total file size: ${newContent.length} characters`);
    
  } catch (error) {
    console.error('❌ Error adding tools:', error);
    process.exit(1);
  }
}

// Run the process
addBasicTools();
