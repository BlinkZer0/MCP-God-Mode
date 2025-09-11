import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerVideoEditor } from "./video_editor.js";

export function registerVideoEditing(server: McpServer) {
  registerVideoEditor(server);
}
