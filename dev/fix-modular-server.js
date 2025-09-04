#!/usr/bin/env node

import { readFileSync, writeFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🔧 Fixing modular server structure...\n');

// Read the current modular server file
const modularServerPath = join(__dirname, 'src', 'server-modular.ts');
let modularServerContent = readFileSync(modularServerPath, 'utf8');

// Remove the misplaced tool registrations that are before the server declaration
const lines = modularServerContent.split('\n');
const newLines = [];
let skipUntilServer = false;
let inImportSection = true;

for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  
  // Skip tool registrations that are misplaced
  if (line.includes('registerFsReadText(server)') || 
      line.includes('registerFsWriteText(server)') ||
      line.includes('registerFsSearch(server)') ||
      line.includes('registerFileOps(server)') ||
      line.includes('registerProcRun(server)') ||
      line.includes('registerProcRunElevated(server)') ||
      line.includes('registerGitStatus(server)') ||
      line.includes('registerDownloadFile(server)') ||
      line.includes('registerNetworkDiagnostics(server)') ||
      line.includes('registerCalculator(server)') ||
      line.includes('registerMathCalculate(server)') ||
      line.includes('registerReadEmails(server)') ||
      line.includes('registerDeleteEmails(server)') ||
      line.includes('registerSortEmails(server)') ||
      line.includes('registerManageEmailAccounts(server)') ||
      line.includes('registerVideoEditing(server)') ||
      line.includes('registerOcrTool(server)') ||
      line.includes('registerWebScraper(server)')) {
    continue; // Skip these lines
  }
  
  // Keep the line
  newLines.push(line);
}

// Write the cleaned file
writeFileSync(modularServerPath, newLines.join('\n'), 'utf8');

console.log('✅ Removed misplaced tool registrations!');
console.log('🔄 Now adding tools in the correct location...');

// Now add the tools in the correct location
let updatedContent = newLines.join('\n');

// Find the correct location to add tool registrations (after the server declaration)
const serverDeclarationIndex = updatedContent.indexOf('const server = new McpServer');
if (serverDeclarationIndex !== -1) {
  // Find the end of the server declaration section
  const afterServerSection = updatedContent.indexOf('// Register core tools', serverDeclarationIndex);
  
  if (afterServerSection !== -1) {
    // Insert the missing tool registrations after the existing ones
    const beforeTools = updatedContent.slice(0, afterServerSection);
    const afterTools = updatedContent.slice(afterServerSection);
    
    const additionalTools = `
// Register file system tools
registerFsList(server);
registerFsReadText(server);
registerFsWriteText(server);
registerFsSearch(server);
registerFileOps(server);

// Register process tools
registerProcRun(server);
registerProcRunElevated(server);

// Register git tools
registerGitStatus(server);

// Register network tools
registerPacketSniffer(server);
registerDownloadFile(server);
registerNetworkDiagnostics(server);

// Register utility tools
registerDiceRolling(server);
registerCalculator(server);
registerMathCalculate(server);

// Register email tools
registerSendEmail(server);
registerParseEmail(server);
registerReadEmails(server);
registerDeleteEmails(server);
registerSortEmails(server);
registerManageEmailAccounts(server);

// Register media tools
registerAudioEditing(server);
registerScreenshot(server);
registerImageEditing(server);
registerVideoEditing(server);
registerOcrTool(server);

// Register web tools
registerBrowserControl(server);
registerWebScraper(server);
`;

    updatedContent = beforeTools + additionalTools + afterTools;
  }
}

// Write the updated file
writeFileSync(modularServerPath, updatedContent, 'utf8');

console.log('✅ Modular server structure fixed!');
console.log('🔄 Please rebuild the modular server with: npm run build:modular');
