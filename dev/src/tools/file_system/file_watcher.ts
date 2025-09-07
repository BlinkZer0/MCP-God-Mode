import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import * as fs from "node:fs";
import * as path from "node:path";

const FileWatcherSchema = z.object({
  action: z.enum(["watch", "unwatch", "list_watchers", "get_events"]),
  path: z.string().optional(),
  recursive: z.boolean().default(false),
  events: z.array(z.enum(["change", "rename", "error"])).default(["change"]),
  watcher_id: z.string().optional(),
});

const fileWatchers = new Map<string, fs.FSWatcher>();
const watcherEvents = new Map<string, any[]>();

export function registerFileWatcher(server: McpServer) {
  server.registerTool("file_watcher", {
    description: "Advanced file system watching and monitoring capabilities",
    inputSchema: FileWatcherSchema.shape,
  }, async ({ action, path: watchPath, recursive, events, watcher_id }) => {
      try {
        switch (action) {
          case "watch":
            if (!watchPath) {
              throw new Error("Path is required for watch action");
            }
            
            const watcher = fs.watch(watchPath, { recursive }, (eventType, filename) => {
              const event = {
                timestamp: new Date().toISOString(),
                event: eventType,
                filename,
                path: watchPath,
              };
              
              if (!watcherEvents.has(watcher_id || watchPath)) {
                watcherEvents.set(watcher_id || watchPath, []);
              }
              watcherEvents.get(watcher_id || watchPath)!.push(event);
            });
            
            fileWatchers.set(watcher_id || watchPath, watcher);
            return {
              content: [{
                type: "text",
                text: JSON.stringify({
                  success: true,
                  watcher_id: watcher_id || watchPath,
                  message: `Started watching ${watchPath}`,
                  events: events,
                }, null, 2)
              }]
            };
            
          case "unwatch":
            const targetId = watcher_id || watchPath;
            if (!targetId) {
              throw new Error("Watcher ID or path is required for unwatch action");
            }
            
            const targetWatcher = fileWatchers.get(targetId);
            if (targetWatcher) {
              targetWatcher.close();
              fileWatchers.delete(targetId);
              watcherEvents.delete(targetId);
              return {
                content: [{
                  type: "text",
                  text: JSON.stringify({
                    success: true,
                    message: `Stopped watching ${targetId}`,
                  }, null, 2)
                }]
              };
            } else {
              throw new Error(`No active watcher found for ${targetId}`);
            }
            
          case "list_watchers":
            return {
              content: [{
                type: "text",
                text: JSON.stringify({
                  success: true,
                  watchers: Array.from(fileWatchers.keys()).map(id => ({
                    id,
                    path: id,
                    active: true,
                  })),
                  count: fileWatchers.size,
                }, null, 2)
              }]
            };
            
          case "get_events":
            const targetEventsId = watcher_id || watchPath;
            if (!targetEventsId) {
              throw new Error("Watcher ID or path is required for get_events action");
            }
            
            const events_list = watcherEvents.get(targetEventsId) || [];
            return {
              content: [{
                type: "text",
                text: JSON.stringify({
                  success: true,
                  watcher_id: targetEventsId,
                  events: events_list,
                  count: events_list.length,
                }, null, 2)
              }]
            };
            
          default:
            throw new Error(`Unknown action: ${action}`);
        }
      } catch (error) {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              success: false,
              error: error instanceof Error ? error.message : "Unknown error",
            }, null, 2)
          }]
        };
      }
    });
}
