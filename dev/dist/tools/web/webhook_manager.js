import { z } from "zod";
import { createServer } from "node:http";
import { URL } from "node:url";
const WebhookManagerSchema = z.object({
    action: z.enum(["create", "list", "delete", "test", "monitor", "get_logs", "configure"]),
    webhook_id: z.string().optional(),
    name: z.string().optional(),
    url: z.string().optional(),
    method: z.enum(["GET", "POST", "PUT", "DELETE"]).default("POST"),
    headers: z.record(z.string()).optional(),
    payload: z.any().optional(),
    port: z.number().default(3000),
    timeout: z.number().default(5000),
    retry_count: z.number().default(3),
    secret: z.string().optional(),
});
const webhooks = new Map();
const webhookLogs = new Map();
let webhookServer = null;
export function registerWebhookManager(server) {
    server.registerTool("webhook_manager", {
        description: "Advanced webhook creation, management, and monitoring toolkit",
    }, async ({ action, webhook_id, name, url, method, headers, payload, port, timeout, retry_count, secret }) => {
        try {
            switch (action) {
                case "create":
                    if (!name || !url) {
                        throw new Error("Name and URL are required for create action");
                    }
                    const webhook = {
                        id: webhook_id || `webhook_${Date.now()}`,
                        name,
                        url,
                        method,
                        headers: headers || {},
                        payload: payload || {},
                        port,
                        timeout,
                        retry_count,
                        secret: secret || "",
                        created: new Date().toISOString(),
                        last_triggered: null,
                        trigger_count: 0,
                        status: "active",
                    };
                    webhooks.set(webhook.id, webhook);
                    // Start webhook server if not already running
                    if (!webhookServer) {
                        startWebhookServer(port);
                    }
                    return {
                        success: true,
                        message: `Webhook '${name}' created successfully`,
                        webhook_id: webhook.id,
                        webhook,
                    };
                case "list":
                    return {
                        success: true,
                        message: `Found ${webhooks.size} webhooks`,
                        webhooks: Array.from(webhooks.values()),
                        count: webhooks.size,
                    };
                case "delete":
                    if (!webhook_id) {
                        throw new Error("Webhook ID is required for delete action");
                    }
                    const deletedWebhook = webhooks.get(webhook_id);
                    if (deletedWebhook) {
                        webhooks.delete(webhook_id);
                        webhookLogs.delete(webhook_id);
                        return {
                            success: true,
                            message: `Webhook '${deletedWebhook.name}' deleted successfully`,
                            deleted_webhook: deletedWebhook,
                        };
                    }
                    else {
                        throw new Error(`No webhook found with ID: ${webhook_id}`);
                    }
                case "test":
                    if (!webhook_id) {
                        throw new Error("Webhook ID is required for test action");
                    }
                    const testWebhook = webhooks.get(webhook_id);
                    if (!testWebhook) {
                        throw new Error(`No webhook found with ID: ${webhook_id}`);
                    }
                    try {
                        const response = await triggerWebhook(testWebhook, {
                            test: true,
                            timestamp: new Date().toISOString(),
                            message: "Test webhook trigger",
                        });
                        return {
                            success: true,
                            message: `Webhook '${testWebhook.name}' tested successfully`,
                            webhook_id,
                            test_response: response,
                            status: "Triggered",
                        };
                    }
                    catch (error) {
                        return {
                            success: false,
                            error: `Webhook test failed: ${error instanceof Error ? error.message : "Unknown error"}`,
                            webhook_id,
                        };
                    }
                case "monitor":
                    if (!webhook_id) {
                        throw new Error("Webhook ID is required for monitor action");
                    }
                    const monitorWebhook = webhooks.get(webhook_id);
                    if (!monitorWebhook) {
                        throw new Error(`No webhook found with ID: ${webhook_id}`);
                    }
                    const logs = webhookLogs.get(webhook_id) || [];
                    return {
                        success: true,
                        message: `Webhook monitoring data retrieved for '${monitorWebhook.name}'`,
                        webhook_id,
                        webhook: monitorWebhook,
                        logs: logs.slice(-50), // Last 50 logs
                        total_logs: logs.length,
                        last_triggered: monitorWebhook.last_triggered,
                        trigger_count: monitorWebhook.trigger_count,
                    };
                case "get_logs":
                    if (!webhook_id) {
                        throw new Error("Webhook ID is required for get_logs action");
                    }
                    const logs = webhookLogs.get(webhook_id) || [];
                    return {
                        success: true,
                        message: `Webhook logs retrieved`,
                        webhook_id,
                        logs,
                        total_logs: logs.length,
                        log_summary: {
                            successful: logs.filter(log => log.success).length,
                            failed: logs.filter(log => !log.success).length,
                            total_requests: logs.length,
                        },
                    };
                case "configure":
                    if (!webhook_id) {
                        throw new Error("Webhook ID is required for configure action");
                    }
                    const configWebhook = webhooks.get(webhook_id);
                    if (!configWebhook) {
                        throw new Error(`No webhook found with ID: ${webhook_id}`);
                    }
                    // Update webhook configuration
                    if (name)
                        configWebhook.name = name;
                    if (url)
                        configWebhook.url = url;
                    if (method)
                        configWebhook.method = method;
                    if (headers)
                        configWebhook.headers = { ...configWebhook.headers, ...headers };
                    if (payload)
                        configWebhook.payload = payload;
                    if (port)
                        configWebhook.port = port;
                    if (timeout)
                        configWebhook.timeout = timeout;
                    if (retry_count)
                        configWebhook.retry_count = retry_count;
                    if (secret)
                        configWebhook.secret = secret;
                    return {
                        success: true,
                        message: `Webhook '${configWebhook.name}' configured successfully`,
                        webhook_id,
                        updated_webhook: configWebhook,
                    };
                default:
                    throw new Error(`Unknown action: ${action}`);
            }
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : "Unknown error",
            };
        }
    });
}
// Helper function to start webhook server
function startWebhookServer(port) {
    webhookServer = createServer((req, res) => {
        if (req.method === "POST") {
            let body = "";
            req.on("data", (chunk) => {
                body += chunk.toString();
            });
            req.on("end", () => {
                try {
                    const payload = JSON.parse(body);
                    const url = new URL(req.url || "", `http://${req.headers.host}`);
                    const webhookId = url.searchParams.get("webhook_id");
                    if (webhookId && webhooks.has(webhookId)) {
                        const webhook = webhooks.get(webhookId);
                        // Log the incoming webhook
                        const logEntry = {
                            timestamp: new Date().toISOString(),
                            webhook_id: webhookId,
                            method: req.method,
                            headers: req.headers,
                            payload,
                            success: true,
                        };
                        if (!webhookLogs.has(webhookId)) {
                            webhookLogs.set(webhookId, []);
                        }
                        webhookLogs.get(webhookId).push(logEntry);
                        // Update webhook stats
                        webhook.last_triggered = new Date().toISOString();
                        webhook.trigger_count++;
                        // Trigger the webhook
                        triggerWebhook(webhook, payload).catch(console.error);
                        res.writeHead(200, { "Content-Type": "application/json" });
                        res.end(JSON.stringify({ success: true, message: "Webhook received" }));
                    }
                    else {
                        res.writeHead(404, { "Content-Type": "application/json" });
                        res.end(JSON.stringify({ success: false, error: "Webhook not found" }));
                    }
                }
                catch (error) {
                    res.writeHead(400, { "Content-Type": "application/json" });
                    res.end(JSON.stringify({ success: false, error: "Invalid JSON payload" }));
                }
            });
        }
        else {
            res.writeHead(405, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ success: false, error: "Method not allowed" }));
        }
    });
    webhookServer.listen(port, () => {
        console.log(`Webhook server started on port ${port}`);
    });
    webhookServer.on("error", (error) => {
        console.error("Webhook server error:", error);
    });
}
// Helper function to trigger a webhook
async function triggerWebhook(webhook, payload) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        webhook_id: webhook.id,
        action: "outgoing",
        url: webhook.url,
        method: webhook.method,
        payload,
        success: false,
        error: null,
    };
    try {
        const response = await fetch(webhook.url, {
            method: webhook.method,
            headers: {
                "Content-Type": "application/json",
                ...webhook.headers,
            },
            body: JSON.stringify(payload),
            signal: AbortSignal.timeout(webhook.timeout),
        });
        if (response.ok) {
            logEntry.success = true;
            const responseData = await response.text();
            if (!webhookLogs.has(webhook.id)) {
                webhookLogs.set(webhook.id, []);
            }
            webhookLogs.get(webhook.id).push(logEntry);
            return {
                status: response.status,
                statusText: response.statusText,
                headers: Object.fromEntries(response.headers.entries()),
                data: responseData,
            };
        }
        else {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
    }
    catch (error) {
        logEntry.error = error instanceof Error ? error.message : "Unknown error";
        if (!webhookLogs.has(webhook.id)) {
            webhookLogs.set(webhook.id, []);
        }
        webhookLogs.get(webhook.id).push(logEntry);
        // Retry logic
        if (webhook.retry_count > 0) {
            for (let i = 0; i < webhook.retry_count; i++) {
                try {
                    await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1))); // Exponential backoff
                    const retryResponse = await fetch(webhook.url, {
                        method: webhook.method,
                        headers: {
                            "Content-Type": "application/json",
                            ...webhook.headers,
                        },
                        body: JSON.stringify(payload),
                        signal: AbortSignal.timeout(webhook.timeout),
                    });
                    if (retryResponse.ok) {
                        const retryLogEntry = {
                            timestamp: new Date().toISOString(),
                            webhook_id: webhook.id,
                            action: "retry_success",
                            attempt: i + 1,
                            success: true,
                        };
                        webhookLogs.get(webhook.id).push(retryLogEntry);
                        return {
                            status: retryResponse.status,
                            statusText: retryResponse.statusText,
                            headers: Object.fromEntries(retryResponse.headers.entries()),
                            retry_attempts: i + 1,
                        };
                    }
                }
                catch (retryError) {
                    const retryLogEntry = {
                        timestamp: new Date().toISOString(),
                        webhook_id: webhook.id,
                        action: "retry_failed",
                        attempt: i + 1,
                        error: retryError instanceof Error ? retryError.message : "Unknown error",
                    };
                    webhookLogs.get(webhook.id).push(retryLogEntry);
                }
            }
        }
        throw error;
    }
}
