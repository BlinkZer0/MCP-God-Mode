/**
 * Flipper Zero File System Operations
 */
import { getSession, audit } from '../session.js';
import { parseFileList } from '../rpc/rpcClient.js';
/**
 * List files in a directory
 */
export async function listFiles(sessionId, path = '/') {
    const session = getSession(sessionId);
    try {
        const response = await session.rpc.fsList(path);
        const files = parseFileList(response);
        audit('fs_list', {
            sessionId,
            deviceId: session.transport.id,
            path,
            fileCount: files.length
        });
        return {
            success: true,
            data: {
                path,
                files,
                rawResponse: response
            }
        };
    }
    catch (error) {
        audit('fs_list_error', {
            sessionId,
            deviceId: session.transport.id,
            path,
            error: error instanceof Error ? error.message : String(error)
        });
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
}
/**
 * Read file contents
 */
export async function readFile(sessionId, path) {
    const session = getSession(sessionId);
    try {
        const response = await session.rpc.fsRead(path);
        audit('fs_read', {
            sessionId,
            deviceId: session.transport.id,
            path,
            payload: { length: response.join('\n').length }
        });
        return {
            success: true,
            data: {
                path,
                content: response.join('\n'),
                rawResponse: response
            }
        };
    }
    catch (error) {
        audit('fs_read_error', {
            sessionId,
            deviceId: session.transport.id,
            path,
            error: error instanceof Error ? error.message : String(error)
        });
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
}
/**
 * Write file contents
 */
export async function writeFile(sessionId, path, content) {
    const session = getSession(sessionId);
    try {
        // Begin write operation
        await session.rpc.fsWriteBegin(path, content.length);
        // Write data
        await session.rpc.fsWriteData(content);
        // End write operation
        const response = await session.rpc.fsWriteEnd();
        audit('fs_write', {
            sessionId,
            deviceId: session.transport.id,
            path,
            payload: { length: content.length }
        });
        return {
            success: true,
            data: {
                path,
                bytesWritten: content.length,
                rawResponse: response
            }
        };
    }
    catch (error) {
        audit('fs_write_error', {
            sessionId,
            deviceId: session.transport.id,
            path,
            error: error instanceof Error ? error.message : String(error)
        });
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
}
/**
 * Delete file
 */
export async function deleteFile(sessionId, path) {
    const session = getSession(sessionId);
    try {
        const response = await session.rpc.fsDelete(path);
        audit('fs_delete', {
            sessionId,
            deviceId: session.transport.id,
            path
        });
        return {
            success: true,
            data: {
                path,
                rawResponse: response
            }
        };
    }
    catch (error) {
        audit('fs_delete_error', {
            sessionId,
            deviceId: session.transport.id,
            path,
            error: error instanceof Error ? error.message : String(error)
        });
        return {
            success: false,
            error: error instanceof Error ? error.message : String(error)
        };
    }
}
