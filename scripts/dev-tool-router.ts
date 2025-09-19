import { spawn } from 'node:child_process';
import path from 'node:path';

const SERVER_PATH = path.join(process.cwd(), 'servers', 'tool-router.js');

const server = spawn('node', [SERVER_PATH], {
  stdio: 'inherit',
  shell: process.platform === 'win32'
});

server.on('error', (err) => {
  console.error('Server error:', err);
});

server.on('close', (code) => {
  console.log(`Server exited with code ${code}`);
});

process.on('SIGINT', () => {
  server.kill();
  process.exit();
});
