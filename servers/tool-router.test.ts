import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs/promises';

const SERVER_PATH = path.join(process.cwd(), 'servers', 'tool-router.js');
const REGISTRY_PATH = path.join(process.cwd(), 'servers', 'router-registry', 'tools.json');

describe('tool-router', () => {
  let serverProcess;
  let client;
  
  before(async () => {
    // Start server
    serverProcess = spawn('node', [SERVER_PATH], { stdio: 'pipe' });
    
    // Wait for ready message
    await new Promise((resolve) => {
      serverProcess.stderr.on('data', (data) => {
        if (data.includes('ready')) resolve();
      });
    });
  });
  
  after(() => {
    serverProcess.kill();
  });
  
  it('should list tools', async () => {
    const response = await client.request('tool.list_catalog', {});
    assert(response.total >= 1);
    assert(response.items.length > 0);
  });
  
  it('should describe tools', async () => {
    const response = await client.request('tool.describe', { name: 'demo.echo' });
    assert(response.name === 'demo.echo');
    assert(response.input_schema);
    assert(response.output_schema);
  });
  
  it('should call tools', async () => {
    const response = await client.request('tool.call', {
      name: 'demo.echo',
      args: { text: 'test' }
    });
    assert(response.ok === true);
    assert(response.echo.text === 'test');
  });
  
  it('should reject version mismatches', async () => {
    const response = await client.request('tool.call', {
      name: 'demo.echo',
      version: '2.0.0',
      args: { text: 'test' }
    });
    assert(response.error.failure_class === 'version_mismatch');
  });
  
  it('should handle hot-reload', async () => {
    // Add new tool to registry
    const registry = JSON.parse(await fs.readFile(REGISTRY_PATH, 'utf8'));
    registry.push({
      name: 'demo.echo2',
      version: '1.0.0',
      summary: 'Second echo',
      input_schema: { type: 'object', properties: { text: { type: 'string' } } },
      output_schema: { type: 'object', properties: { ok: { type: 'boolean' } } },
      handlerPath: 'handlers/echo.js'
    });
    await fs.writeFile(REGISTRY_PATH, JSON.stringify(registry));
    
    // Wait for reload
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Verify new tool appears
    const list = await client.request('tool.list_catalog', {});
    assert(list.items.some(t => t.name === 'demo.echo2'));
  });
});
