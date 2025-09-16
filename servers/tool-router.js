import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import fs from "node:fs/promises";
import { watch } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import Ajv from "ajv";
import addFormats from "ajv-formats";

// Simple mutex implementation for concurrency control
class Mutex {
  constructor() {
    this.queue = [];
    this.locked = false;
  }

  acquire() {
    return new Promise(resolve => {
      if (!this.locked) {
        this.locked = true;
        resolve(this.release.bind(this));
      } else {
        this.queue.push(resolve);
      }
    });
  }

  release() {
    if (this.queue.length > 0) {
      const next = this.queue.shift();
      next(this.release.bind(this));
    } else {
      this.locked = false;
    }
  }
}

// Metrics collection
const metrics = {
  calls: 0,
  errors: 0,
  timeouts: 0,
  reloads: 0,
  lastError: null,
  lastReload: null,
  lastErrorTime: null,
  startTime: Date.now(),
  get uptime() {
    return Date.now() - this.startTime;
  },
  recordCall() {
    this.calls++;
  },
  recordError(error) {
    this.errors++;
    this.lastError = error?.message || String(error);
    this.lastErrorTime = new Date().toISOString();
  },
  recordTimeout() {
    this.timeouts++;
  },
  recordReload() {
    this.reloads++;
    this.lastReload = new Date().toISOString();
  },
  getStats() {
    return {
      calls: this.calls,
      errors: this.errors,
      timeouts: this.timeouts,
      reloads: this.reloads,
      uptime: this.uptime,
      lastError: this.lastError,
      lastErrorTime: this.lastErrorTime,
      lastReload: this.lastReload,
      currentLoad: inFlight / MAX_INFLIGHT * 100,
      registrySize: registry.size
    };
  }
};

// Initialize Ajv with formats and caching
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const validatorCache = new Map();

/**
 * Compiles and caches JSON schemas for validation
 * @param {object} schema - JSON Schema to compile
 * @returns {Function} Compiled validation function
 */
function getValidator(schema) {
  const key = JSON.stringify(schema);
  let v = validatorCache.get(key);
  if (!v) {
    try {
      v = ajv.compile(schema);
      validatorCache.set(key, v);
    } catch (error) {
      console.error(`[${NAME}] Failed to compile schema:`, error);
      throw new Error(`Invalid schema: ${error.message}`);
    }
  }
  return v;
}

/**
 * Validates input against a JSON schema
 * @param {object} schema - JSON Schema to validate against
 * @param {*} args - Input to validate
 * @returns {{ok: boolean, errors: string[]}} Validation result
 */
function validateInput(schema, args) {
  try {
    const v = getValidator(schema);
    const valid = v(args);
    return { 
      ok: !!valid, 
      errors: valid ? [] : (v.errors || []).map(e => `${e.instancePath} ${e.message}`.trim() || 'Validation failed')
    };
  } catch (error) {
    console.error(`[${NAME}] Validation error:`, error);
    return {
      ok: false,
      errors: [error.message || 'Validation failed']
    };
  }
}

/**
 * Wraps a promise with a timeout
 * @param {Promise} promise - Promise to wrap
 * @param {number} ms - Timeout in milliseconds
 * @returns {Promise<{timeout: boolean, value?: any, error?: Error}>} Result with timeout flag
 */
function withTimeout(promise, ms) {
  return new Promise((resolve) => {
    const t = setTimeout(() => {
      console.warn(`[${NAME}] Operation timed out after ${ms}ms`);
      resolve({ timeout: true });
    }, ms);
    
    promise.then(
      (v) => { 
        clearTimeout(t); 
        resolve({ value: v }); 
      },
      (e) => { 
        clearTimeout(t); 
        resolve({ error: e }); 
      }
    ).catch(error => {
      console.error(`[${NAME}] Unhandled error in withTimeout:`, error);
      clearTimeout(t);
      resolve({ error });
    });
  });
}

const NAME = "tool-router";
const VERSION = "1.0.0";
const ROOT = path.resolve(process.cwd(), "servers", "router-registry");
const CATALOG = path.join(ROOT, "tools.json");
const MAX_INFLIGHT = 8;
const CALL_TIMEOUT_MS = 90_000;
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 100;

// In-memory registry and mutex for thread-safe access
const registryMutex = new Mutex();
let registry = new Map();
let watcher = null; // File system watcher
let reloading = false; // Track if a reload is in progress

/**
 * Validates and normalizes a handler path to prevent directory traversal
 * @param {string} handlerPath - Relative or absolute path to validate
 * @returns {string} Resolved absolute path
 * @throws {Error} If the path is invalid or outside the allowed directory
 */
function validateHandlerPath(handlerPath) {
  if (typeof handlerPath !== 'string' || !handlerPath.trim()) {
    throw new Error('Handler path must be a non-empty string');
  }
  
  const resolvedPath = path.isAbsolute(handlerPath) 
    ? path.normalize(handlerPath)
    : path.normalize(path.join(ROOT, handlerPath));
  
  // Prevent directory traversal
  if (!resolvedPath.startsWith(ROOT)) {
    throw new Error(`Handler path must be inside ${ROOT}`);
  }
  
  // Basic extension check
  if (!resolvedPath.endsWith('.js') && !resolvedPath.endsWith('.mjs')) {
    throw new Error('Handler must be a JavaScript file (.js or .mjs)');
  }
  
  return resolvedPath;
}

/**
 * Safely reads a file with retries and error handling
 * @param {string} filePath - Path to the file to read
 * @param {number} [retries=MAX_RETRIES] - Number of retry attempts
 * @returns {Promise<string>} File contents
 * @throws {Error} If file cannot be read after retries
 */
async function safeReadFile(filePath, retries = MAX_RETRIES) {
  let lastError;
  
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await fs.readFile(filePath, 'utf8');
    } catch (error) {
      lastError = error;
      if (attempt < retries) {
        // Exponential backoff
        const delay = RETRY_DELAY_MS * Math.pow(2, attempt - 1);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  throw new Error(`Failed to read ${filePath} after ${retries} attempts: ${lastError?.message || lastError}`);
}

/**
 * Validates tool schema and required fields
 * @param {object} tool - Tool definition to validate
 * @throws {Error} If the tool definition is invalid
 */
function validateToolSchema(tool) {
  if (!tool || typeof tool !== 'object') {
    throw new Error('Tool must be an object');
  }
  
  const requiredFields = ['name', 'version', 'handlerPath', 'input_schema', 'output_schema'];
  const missingFields = requiredFields.filter(field => !(field in tool));
  
  if (missingFields.length > 0) {
    throw new Error(`Missing required fields: ${missingFields.join(', ')}`);
  }
  
  if (typeof tool.name !== 'string' || !tool.name.trim()) {
    throw new Error('Tool name must be a non-empty string');
  }
  
  if (typeof tool.handlerPath !== 'string' || !tool.handlerPath.trim()) {
    throw new Error('Handler path must be a non-empty string');
  }
  
  // Validate handler path format (actual file existence is checked separately)
  try {
    validateHandlerPath(tool.handlerPath);
  } catch (error) {
    throw new Error(`Invalid handler path for ${tool.name}: ${error.message}`);
  }
  
  // Basic schema validation
  if (typeof tool.input_schema !== 'object' || tool.input_schema === null) {
    throw new Error('input_schema must be an object');
  }
  
  if (typeof tool.output_schema !== 'object' || tool.output_schema === null) {
    throw new Error('output_schema must be an object');
  }
}

/**
 * Loads and validates the tool catalog from the filesystem
 * @returns {Promise<Map>} A map of tool names to tool definitions
 */
async function loadCatalog() {
  try {
    const raw = await safeReadFile(CATALOG);
    const items = JSON.parse(raw);
    
    if (!Array.isArray(items)) {
      throw new Error('Catalog must be an array of tool definitions');
    }
    
    const next = new Map();
    const errors = [];
    
    for (const [index, item] of items.entries()) {
      try {
        validateToolSchema(item);
        // Ensure handler exists and is accessible
        const handlerPath = validateHandlerPath(item.handlerPath);
        await fs.access(handlerPath);
        
        next.set(item.name, {
          ...item,
          // Store the resolved absolute path
          _resolvedHandlerPath: handlerPath,
          // Add default values for optional fields
          tags: Array.isArray(item.tags) ? item.tags : [],
          description: item.description || '',
          summary: item.summary || ''
        });
      } catch (error) {
        errors.push(`Error in tool #${index + 1} (${item?.name || 'unnamed'}): ${error.message}`);
      }
    }
    
    if (errors.length > 0) {
      console.error(`[${NAME}] Errors loading tools:\n${errors.join('\n')}`);
      if (next.size === 0) {
        throw new Error('No valid tools found in catalog');
      }
    }
    
    return next;
  } catch (error) {
    metrics.recordError(error);
    console.error(`[${NAME}] Failed to load catalog:`, error);
    throw error;
  }
}
await loadCatalog();

/**
 * Reloads the tool catalog with debouncing
 */
async function reloadSoon() {
  if (reloading) return;
  reloading = true;
  
  try {
    await new Promise(resolve => setTimeout(resolve, 300)); // Debounce
    const release = await registryMutex.acquire();
    
    try {
      const newRegistry = await loadCatalog();
      registry = newRegistry;
      metrics.recordReload();
      console.error(`[${NAME}] Registry reloaded (${registry.size} tools)`);
    } finally {
      release();
    }
  } catch (error) {
    metrics.recordError(error);
    console.error(`[${NAME}] Failed to reload registry:`, error);
  } finally {
    reloading = false;
  }
}

/**
 * Initializes the file system watcher
 */
function setupFileWatcher() {
  if (watcher) {
    watcher.close();
  }
  
  watcher = watch(CATALOG, { persistent: false }, (eventType) => {
    if (eventType === 'change') {
      console.error(`[${NAME}] Detected changes to ${CATALOG}, scheduling reload...`);
      reloadSoon().catch(error => {
        console.error(`[${NAME}] Error during reload:`, error);
      });
    }
  });
  
  watcher.on('error', (error) => {
    console.error(`[${NAME}] File watcher error:`, error);
    // Attempt to recover by recreating the watcher
    if (watcher) {
      watcher.close();
      setupFileWatcher();
    }
  });
  
  // Clean up on process exit
  process.on('exit', () => {
    if (watcher) {
      watcher.close();
    }
  });
}

// Reuse validateInput for output validation
const validateOutput = validateInput;

// Concurrency control - track active operations
let inFlight = 0; // Track concurrent operations

// Initialize the server and register tools
const server = new McpServer({ name: NAME, version: VERSION });

// Register the tool.list_catalog endpoint
server.registerTool("tool.list_catalog",
  {
    title: "List Tools",
    description: "List all available tools with optional filtering and pagination",
    inputSchema: {
      type: "object",
      properties: {
        q: { type: "string", description: "Search query string" },
        tags: { 
          type: "array", 
          items: { type: "string" },
          description: "Filter tools by tags"
        },
        page: { 
          type: "integer", 
          minimum: 1,
          default: 1,
          description: "Page number for pagination"
        },
        pageSize: {
          type: "integer",
          minimum: 1,
          maximum: 100,
          default: 20,
          description: "Number of items per page"
        }
      },
      additionalProperties: false
    }
  },
  async ({ q = "", tags = [], page = 1, pageSize = 20 }) => {
    try {
      metrics.recordCall();
      const allTools = Array.from(registry.values());
      
      // Filter tools by search query and tags
      const filtered = allTools.filter(tool => {
        const matchesSearch = !q || 
          tool.name.toLowerCase().includes(q.toLowerCase()) ||
          tool.summary.toLowerCase().includes(q.toLowerCase()) ||
          tool.description.toLowerCase().includes(q.toLowerCase());
          
        const matchesTags = !tags.length || 
          tags.every(tag => tool.tags.map(t => t.toLowerCase()).includes(tag.toLowerCase()));
          
        return matchesSearch && matchesTags;
      });
      
      // Apply pagination
      const start = (page - 1) * pageSize;
      const paginated = filtered.slice(start, start + pageSize);
      
      // Remove internal fields from the response
      const result = paginated.map(({ _resolvedHandlerPath, ...tool }) => tool);
      
      return {
        content: [{
          type: "json",
          json: {
            items: result,
            total: filtered.length,
            page,
            pageSize,
            hasMore: start + pageSize < filtered.length
          }
        }]
      };
    } catch (error) {
      metrics.recordError(error);
      return {
        content: [{
          type: "json",
          json: {
            error: {
              code: "internal_error",
              message: "Failed to list tools",
              details: process.env.NODE_ENV === "development" ? error.message : undefined
            }
          }
        }]
      };
    }
  }
);

// Register the tool.describe endpoint
server.registerTool("tool.describe",
  {
    title: "Describe Tool",
    description: "Get detailed information about a specific tool",
    inputSchema: {
      type: "object",
      properties: {
        name: { 
          type: "string",
          description: "Name of the tool to describe"
        }
      },
      required: ["name"],
      additionalProperties: false
    }
  },
  async ({ name }) => {
    try {
      metrics.recordCall();
      const tool = registry.get(name);
      
      if (!tool) {
        return {
          content: [{
            type: "json",
            json: {
              error: {
                code: "not_found",
                message: `Tool '${name}' not found`
              }
            }
          }]
        };
      }
      
      // Remove internal fields from the response
      const { _resolvedHandlerPath, ...publicTool } = tool;
      
      return {
        content: [{
          type: "json",
          json: publicTool
        }]
      };
    } catch (error) {
      metrics.recordError(error);
      return {
        content: [{
          type: "json",
          json: {
            error: {
              code: "internal_error",
              message: "Failed to describe tool",
              details: process.env.NODE_ENV === "development" ? error.message : undefined
            }
          }
        }]
      };
    }
  }
);

// Register the tool.call endpoint
server.registerTool("tool.call",
  {
    title: "Call Tool",
    description: "Execute a tool with the provided arguments",
    inputSchema: {
      type: "object",
      properties: {
        name: { 
          type: "string",
          description: "Name of the tool to execute"
        },
        version: { 
          type: "string",
          description: "Version of the tool to execute (optional)"
        },
        args: { 
          type: "object",
          description: "Arguments to pass to the tool",
          additionalProperties: true
        }
      },
      required: ["name", "args"],
      additionalProperties: false
    }
  },
  async ({ name, version, args = {} }) => {
    const startTime = Date.now();
    
    try {
      metrics.recordCall();
      
      // Check concurrency limit
      if (inFlight >= MAX_INFLIGHT) {
        return {
          content: [{
            type: "json",
            json: {
              error: {
                code: "too_many_requests",
                message: "Server is busy, please try again later",
                retryAfter: 5 // seconds
              }
            }
          }]
        };
      }
      
      // Get the tool definition
      const tool = registry.get(name);
      if (!tool) {
        return {
          content: [{
            type: "json",
            json: {
              error: {
                code: "not_found",
                message: `Tool '${name}' not found`
              }
            }
          }]
        };
      }
      
      // Check version if specified
      if (version && version !== tool.version) {
        return {
          content: [{
            type: "json",
            json: {
              error: {
                code: "version_mismatch",
                message: `Version mismatch: expected ${tool.version}, got ${version}`
              }
            }
          }]
        };
      }
      
      // Validate input against the tool's schema
      const validation = validateInput(tool.input_schema, args);
      if (!validation.ok) {
        return {
          content: [{
            type: "json",
            json: {
              error: {
                code: "invalid_arguments",
                message: "Invalid arguments",
                details: validation.errors
              }
            }
          }]
        };
      }
      
      // Execute the tool with timeout
      inFlight++;
      const result = await withTimeout(
        (async () => {
          try {
            // Dynamic import the handler
            const module = await import(tool._resolvedHandlerPath);
            const handler = module.default || module.handler || module;
            
            if (typeof handler !== 'function') {
              throw new Error('Handler must export a function as default or named export');
            }
            
            // Call the handler with arguments
            return await handler(args);
          } catch (error) {
            metrics.recordError(error);
            throw error;
          } finally {
            inFlight--;
          }
        })(),
        CALL_TIMEOUT_MS
      );
      
      // Handle timeout
      if (result.timeout) {
        metrics.recordTimeout();
        return {
          content: [{
            type: "json",
            json: {
              error: {
                code: "timeout",
                message: `Operation timed out after ${CALL_TIMEOUT_MS}ms`
              }
            }
          }]
        };
      }
      
      // Handle handler errors
      if (result.error) {
        metrics.recordError(result.error);
        return {
          content: [{
            type: "json",
            json: {
              error: {
                code: "execution_error",
                message: "Tool execution failed",
                details: process.env.NODE_ENV === "development" ? result.error.message : undefined
              }
            }
          }]
        };
      }
      
      // Validate output against the tool's output schema
      const outputValidation = validateInput(tool.output_schema, result.value);
      if (!outputValidation.ok) {
        return {
          content: [{
            type: "json",
            json: {
              error: {
                code: "invalid_output",
                message: "Tool returned invalid output",
                details: outputValidation.errors
              }
            }
          }]
        };
      }
      
      // Log successful execution
      const duration = Date.now() - startTime;
      console.log(`[${NAME}] Tool '${name}' executed in ${duration}ms`);
      
      return {
        content: [{
          type: "json",
          json: result.value
        }]
      };
      
    } catch (error) {
      metrics.recordError(error);
      return {
        content: [{
          type: "json",
          json: {
            error: {
              code: "internal_error",
              message: "An unexpected error occurred",
              details: process.env.NODE_ENV === "development" ? error.message : undefined
            }
          }
        }]
      };
    }
  }
);

// Register the tool.metrics endpoint
server.registerTool("tool.metrics",
  {
    title: "Get Metrics",
    description: "Get runtime metrics about the tool router",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false
    }
  },
  async () => {
    try {
      return {
        content: [{
          type: "json",
          json: metrics.getStats()
        }]
      };
    } catch (error) {
      metrics.recordError(error);
      return {
        content: [{
          type: "json",
          json: {
            error: {
              code: "internal_error",
              message: "Failed to get metrics"
            }
          }
        }]
      };
    }
  }
);

// Initialize the server
async function startServer() {
  try {
    // Initial load of the tool catalog
    registry = await loadCatalog();
    
    // Set up file watcher for hot-reload
    setupFileWatcher();
    
    // Set up graceful shutdown
    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
    
    // Start the server
    const transport = new StdioServerTransport();
    server.connect(transport);
    
    console.error(`[${NAME}] Server started with ${registry.size} tools`);
    
  } catch (error) {
    console.error(`[${NAME}] Failed to start server:`, error);
    process.exit(1);
  }
}

// Graceful shutdown handler
async function shutdown() {
  console.error(`[${NAME}] Shutting down...`);
  
  // Close the file watcher
  if (watcher) {
    watcher.close();
  }
  
  // Wait for in-flight requests to complete (with a timeout)
  if (inFlight > 0) {
    console.error(`[${NAME}] Waiting for ${inFlight} in-flight requests to complete...`);
    await Promise.race([
      new Promise(resolve => {
        const check = () => {
          if (inFlight === 0) resolve();
          else setTimeout(check, 100);
        };
        check();
      }),
      new Promise(resolve => setTimeout(resolve, 5000)) // 5s max wait
    ]);
  }
  
  process.exit(0);
}

// Start the server
startServer().catch(error => {
  console.error(`[${NAME}] Fatal error:`, error);
  process.exit(1);
});
