#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');

async function copyEverything() {
  try {
    console.log('🔧 Starting comprehensive tool copying process...');
    
    // Read the current server-refactored.ts file to get the header
    const serverFile = path.join(__dirname, 'src', 'server-refactored.ts');
    let serverContent = await fs.readFile(serverFile, 'utf8');
    
    // Extract the header (imports and basic setup)
    const headerEnd = serverContent.indexOf('// ===========================================');
    const header = serverContent.substring(0, headerEnd);
    
    // Start building the new content
    let newContent = header;
    
    // Add the tools section header
    newContent += '\n// ===========================================\n// ALL TOOLS FROM TOOLS FOLDER\n// ===========================================\n\n';
    
    // Collect all tool implementations
    const toolsDir = path.join(__dirname, 'src', 'tools');
    const toolCategories = await fs.readdir(toolsDir);
    
    for (const category of toolCategories) {
      const categoryPath = path.join(toolsDir, category);
      const stat = await fs.stat(categoryPath);
      
      if (stat.isDirectory()) {
        console.log(`📁 Processing category: ${category}`);
        
        try {
          // Read the index file to see what tools are available
          const indexFile = path.join(categoryPath, 'index.ts');
          const indexContent = await fs.readFile(indexFile, 'utf8');
          
          // Extract tool names from the index file
          const toolMatches = indexContent.match(/export function (register\w+)/g);
          
          if (toolMatches) {
            newContent += `// ===========================================\n// ${category.toUpperCase()} TOOLS\n// ===========================================\n\n`;
            
            for (const toolMatch of toolMatches) {
              const toolName = toolMatch.replace('export function ', '');
              console.log(`  🔧 Processing tool: ${toolName}`);
              
              // Try to find the individual tool file
              const toolFileName = toolName.replace('register', '').toLowerCase();
              const possibleFiles = [
                `${toolFileName}.ts`,
                `${toolFileName.replace(/([A-Z])/g, '_$1').toLowerCase()}.ts`,
                `${toolFileName.replace(/([A-Z])/g, '_$1').toLowerCase()}_tool.ts`
              ];
              
              let toolContent = '';
              for (const fileName of possibleFiles) {
                try {
                  const toolFile = path.join(categoryPath, fileName);
                  const content = await fs.readFile(toolFile, 'utf8');
                  
                  // Extract the tool registration function
                  const functionMatch = content.match(new RegExp(`export function ${toolName}\\(server: McpServer\\) \\{[\\s\\S]*?\\n\\}`, 'g'));
                  
                  if (functionMatch) {
                    toolContent = functionMatch[0]
                      .replace(/export function /g, 'function ')
                      .replace(/import.*?from.*?;?\n?/g, '')
                      .replace(/import.*?from.*?;?\n?/g, '');
                    break;
                  }
                } catch (error) {
                  // File not found, try next one
                }
              }
              
              if (toolContent) {
                newContent += toolContent + '\n\n';
              } else {
                console.log(`    ⚠️  Could not find implementation for ${toolName}`);
              }
            }
          }
        } catch (error) {
          console.log(`⚠️  Could not process ${category}: ${error.message}`);
        }
      }
    }
    
    // Add the tool registration calls
    newContent += '// ===========================================\n// REGISTER ALL TOOLS\n// ===========================================\n\n';
    
    // Get all the tool registration function names
    const toolFunctionMatches = newContent.match(/function (register\w+)/g);
    if (toolFunctionMatches) {
      for (const match of toolFunctionMatches) {
        const functionName = match.replace('function ', '');
        newContent += `${functionName}(server);\n`;
      }
    }
    
    // Add the helper functions and main function
    newContent += `
// ===========================================
// HELPER FUNCTIONS
// ===========================================

// Helper functions for file operations
async function copyDirectoryRecursive(source: string, destination: string): Promise<void> {
  await fs.mkdir(destination, { recursive: true });
  const items = await fs.readdir(source, { withFileTypes: true });
  
  for (const item of items) {
    const sourcePath = path.join(source, item.name);
    const destPath = path.join(destination, item.name);
    
    if (item.isDirectory()) {
      await copyDirectoryRecursive(sourcePath, destPath);
    } else {
      await fs.copyFile(sourcePath, destPath);
    }
  }
}

async function deleteDirectoryRecursive(dirPath: string): Promise<void> {
  const items = await fs.readdir(dirPath, { withFileTypes: true });
  
  for (const item of items) {
    const fullPath = path.join(dirPath, item.name);
    
    if (item.isDirectory()) {
      await deleteDirectoryRecursive(fullPath);
    } else {
      await fs.unlink(fullPath);
    }
  }
  
  await fs.rmdir(dirPath);
}

async function listDirectoryRecursive(dirPath: string, pattern?: string): Promise<string[]> {
  const items: string[] = [];
  
  try {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      
      if (pattern && !entry.name.includes(pattern.replace("*", ""))) {
        continue;
      }
      
      items.push(fullPath);
      
      if (entry.isDirectory()) {
        items.push(...await listDirectoryRecursive(fullPath, pattern));
      }
    }
  } catch (error) {
    // Ignore permission errors
  }
  
  return items;
}

async function findFilesByContent(dirPath: string, searchText: string, recursive: boolean): Promise<string[]> {
  const foundFiles: string[] = [];
  
  try {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      
      if (entry.isDirectory() && recursive) {
        foundFiles.push(...await findFilesByContent(fullPath, searchText, recursive));
      } else if (entry.isFile()) {
        try {
          const content = await fs.readFile(fullPath, "utf8");
          if (content.includes(searchText)) {
            foundFiles.push(fullPath);
          }
        } catch (error) {
          // Ignore read errors
        }
      }
    }
  } catch (error) {
    // Ignore permission errors
  }
  
  return foundFiles;
}

async function compressFile(source: string, destination: string, type: string): Promise<void> {
  if (type === "zip") {
    // Use cross-platform zip command
    const command = IS_WINDOWS ? "powershell" : "zip";
    const args = IS_WINDOWS 
      ? ["-Command", "Compress-Archive -Path \\"" + source + "\\" -DestinationPath \\"" + destination + "\\" -Force"]
      : ["-r", destination, source];
    
    const { stdout, stderr } = await execAsync(command + " " + args.join(" "));
    if (stderr) throw new Error("Compression failed: " + stderr);
  } else {
    throw new Error("Unsupported compression type: " + type);
  }
}

async function decompressFile(source: string, destination: string, type: string): Promise<void> {
  if (type === "zip") {
    // Use cross-platform unzip command
    const command = IS_WINDOWS ? "powershell" : "unzip";
    const args = IS_WINDOWS 
      ? ["-Command", "Expand-Archive -Path \\"" + source + "\\" -DestinationPath \\"" + destination + "\\" -Force"]
      : ["-o", source, "-d", destination];
    
    const { stdout, stderr } = await execAsync(command + " " + args.join(" "));
    if (stderr) throw new Error("Decompression failed: " + stderr);
  } else {
    throw new Error("Unsupported compression type: " + type);
  }
}

async function calculateDirectorySize(dirPath: string): Promise<number> {
  let totalSize = 0;
  
  try {
    const entries = await fs.readdir(dirPath, { withFileTypes: true });
    
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      
      if (entry.isDirectory()) {
        totalSize += await calculateDirectorySize(fullPath);
      } else {
        const stats = await fs.stat(fullPath);
        totalSize += stats.size;
      }
    }
  } catch (error) {
    // Ignore permission errors
  }
  
  return totalSize;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function modeToSymbolic(mode: number): string {
  const permissions = {
    0: "---",
    1: "--x",
    2: "-w-",
    3: "-wx",
    4: "r--",
    5: "r-x",
    6: "rw-",
    7: "rwx"
  };
  
  const owner = permissions[Math.floor(mode / 64) % 8] || "---";
  const group = permissions[Math.floor(mode / 8) % 8] || "---";
  const other = permissions[mode % 8] || "---";
  
  return owner + group + other;
}

async function compareFiles(file1: string, file2: string): Promise<{ identical: boolean; differences: string[] }> {
  try {
    const content1 = await fs.readFile(file1, "utf8");
    const content2 = await fs.readFile(file2, "utf8");
    
    if (content1 === content2) {
      return { identical: true, differences: [] };
    }
    
    // Simple line-by-line comparison
    const lines1 = content1.split("\\n");
    const lines2 = content2.split("\\n");
    const differences: string[] = [];
    
    const maxLines = Math.max(lines1.length, lines2.length);
    for (let i = 0; i < maxLines; i++) {
      if (lines1[i] !== lines2[i]) {
        differences.push("Line " + (i + 1) + ": \\"" + (lines1[i] || '') + "\\" vs \\"" + (lines2[i] || '') + "\\"");
      }
    }
    
    return { identical: false, differences };
  } catch (error) {
    throw new Error("Failed to compare files: " + (error instanceof Error ? error.message : 'Unknown error'));
  }
}

// ===========================================
// MAIN FUNCTION
// ===========================================

async function main() {
  try {
    // Start the server
    const transport = new StdioServerTransport();
    await server.connect(transport);
    
    logger.info("MCP God Mode server started successfully");
    logger.info("Platform: " + PLATFORM);
    logger.info("Allowed roots: " + ALLOWED_ROOTS_ARRAY.join(", "));
    
    // Keep the server running
    process.on("SIGINT", async () => {
      logger.info("Shutting down server...");
      await server.disconnect();
      process.exit(0);
    });
    
    process.on("SIGTERM", async () => {
      logger.info("Shutting down server...");
      await server.disconnect();
      process.exit(0);
    });
    
  } catch (error) {
    logger.error("Failed to start server:", error);
    process.exit(1);
  }
}

// Start the server
main().catch((error) => {
  logger.error("Unhandled error:", error);
  process.exit(1);
});
`;
    
    // Write the updated file
    await fs.writeFile(serverFile, newContent, 'utf8');
    
    console.log('✅ Successfully copied all tools into server-refactored.ts');
    console.log(`📊 Total file size: ${newContent.length} characters`);
    
  } catch (error) {
    console.error('❌ Error copying tools:', error);
    process.exit(1);
  }
}

// Run the copying process
copyEverything();
