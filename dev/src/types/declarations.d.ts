// Type declarations for modules without type definitions

declare module 'simple-git' {
  interface SimpleGit {
    init(): Promise<void>;
    add(files: string | string[]): Promise<void>;
    commit(message: string): Promise<void>;
    push(): Promise<void>;
    pull(): Promise<void>;
    status(): Promise<any>;
    log(): Promise<any>;
    clone(repo: string, path: string): Promise<void>;
  }
  
  function simpleGit(baseDir?: string): SimpleGit;
  export = simpleGit;
}

declare module 'chartjs-node-canvas' {
  export class ChartJSNodeCanvas {
    constructor(options: any);
    renderToBuffer(configuration: any): Promise<Buffer>;
    renderToDataURL(configuration: any): Promise<string>;
  }
}

declare module 'canvas' {
  export function createCanvas(width: number, height: number): any;
  export function createImageData(width: number, height: number): any;
  export function loadImage(src: string): Promise<any>;
}

declare module 'mathjs' {
  export function evaluate(expression: string): any;
  export function parse(expression: string): any;
  export function compile(expression: string): any;
  export const all: any;
  export const create: any;
  export const config: any;
  export const version: string;
}

declare module 'zod' {
  export const z: {
    enum: any;
    string: any;
    number: any;
    boolean: any;
    object: any;
    array: any;
    record: any;
    literal: any;
    union: any;
    optional: any;
    nullable: any;
    default: any;
    parse: any;
    safeParse: any;
    transform: any;
    refine: any;
    pipe: any;
    catch: any;
    brand: any;
    readonly: any;
    describe: any;
    min: any;
    max: any;
    length: any;
    url: any;
    email: any;
    uuid: any;
    date: any;
    datetime: any;
    time: any;
    regex: any;
    includes: any;
    startsWith: any;
    endsWith: any;
    trim: any;
    toLowerCase: any;
    toUpperCase: any;
    nonempty: any;
    minLength: any;
    maxLength: any;
    multipleOf: any;
    int: any;
    positive: any;
    negative: any;
    nonpositive: any;
    nonnegative: any;
    finite: any;
    safe: any;
    create: any;
    ZodError: any;
    ZodIssue: any;
    ZodType: any;
    ZodSchema: any;
    ZodTypeDef: any;
    ZodRawShape: any;
    ZodTypeAny: any;
    ZodNullable: any;
    ZodOptional: any;
    ZodDefault: any;
    ZodReadonly: any;
    ZodBranded: any;
    ZodPipeline: any;
    ZodCatch: any;
    ZodTransform: any;
    ZodRefine: any;
    ZodSuperRefine: any;
    ZodEffects: any;
    ZodIssueCode: any;
    ZodParsedType: any;
    ZodString: any;
    ZodNumber: any;
    ZodBigInt: any;
    ZodBoolean: any;
    ZodDate: any;
    ZodSymbol: any;
    ZodUndefined: any;
    ZodNull: any;
    ZodAny: any;
    ZodUnknown: any;
    ZodNever: any;
    ZodVoid: any;
    ZodArray: any;
    ZodObject: any;
    ZodUnion: any;
    ZodDiscriminatedUnion: any;
    ZodIntersection: any;
    ZodTuple: any;
    ZodRecord: any;
    ZodMap: any;
    ZodSet: any;
    ZodFunction: any;
    ZodLazy: any;
    ZodLiteral: any;
    ZodEnum: any;
    ZodNativeEnum: any;
    ZodOptional: any;
    ZodNullable: any;
    ZodDefault: any;
    ZodReadonly: any;
    ZodBranded: any;
    ZodPipeline: any;
    ZodCatch: any;
    ZodTransform: any;
    ZodRefine: any;
    ZodSuperRefine: any;
    ZodEffects: any;
    ZodIssueCode: any;
    ZodParsedType: any;
  };
  export default z;
}

declare module 'serialport' {
  export class SerialPort {
    constructor(options: any);
    static list(): Promise<any[]>;
    open(): Promise<void>;
    close(): Promise<void>;
    write(data: any): Promise<void>;
    on(event: string, callback: (data: any) => void): void;
    pipe(stream: any): any;
  }
}

// Node.js built-in modules
declare module 'node:path' {
  export * from 'path';
}

declare module 'node:os' {
  export * from 'os';
}

declare module 'node:fs/promises' {
  export * from 'fs/promises';
}

declare module 'node:child_process' {
  export { spawn, exec } from 'child_process';
}

declare module 'node:util' {
  export { promisify } from 'util';
}

declare module 'node:fs' {
  export { createWriteStream, createReadStream } from 'fs';
}

declare module 'node:stream/promises' {
  export { pipeline } from 'stream/promises';
}

declare module 'node:stream' {
  export { Transform, Readable } from 'stream';
}

declare module 'node:crypto' {
  export * from 'crypto';
}

// MCP SDK modules
declare module '@modelcontextprotocol/sdk/server/mcp' {
  export class McpServer {
    constructor(options: any);
    setRequestHandler(method: string, handler: any): void;
    connect(transport: any): Promise<void>;
    registerTool(name: string, toolDefinition: any, handler: any): void;
  }
}

// ws module (runtime dynamic import used in bridge transport)
declare module 'ws' {
  export class WebSocket {
    constructor(url: string, protocols?: string | string[], options?: any);
    on(event: string, handler: (...args: any[]) => void): void;
    onopen: ((ev?: any) => void) | null;
    onclose: ((ev?: any) => void) | null;
    onerror: ((err?: any) => void) | null;
    onmessage: ((ev: { data: any }) => void) | null;
    send(data: any): void;
    close(): void;
  }
  export class WebSocketServer {
    constructor(opts: { port: number } | any);
    on(event: 'connection', handler: (ws: WebSocket) => void): void;
  }
  export default WebSocket;
}

declare module '@modelcontextprotocol/sdk/server/stdio' {
  export class StdioServerTransport {
    constructor();
  }
}
