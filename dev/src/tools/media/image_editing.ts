import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerImageEditor } from "./image_editor.js";

export function registerImageEditing(server: McpServer) {
  registerImageEditor(server);
}
