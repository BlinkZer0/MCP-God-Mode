import { McpServer } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
// Import only the new security tools
import { registerSiemToolkit } from "./tools/security/siem_toolkit.js";
import { registerCloudSecurityAssessment } from "./tools/security/cloud_security_assessment.js";
import { registerApiSecurityTesting } from "./tools/security/api_security_testing.js";
import { registerEmailSecuritySuite } from "./tools/security/email_security_suite.js";
import { registerDatabaseSecurityToolkit } from "./tools/security/database_security_toolkit.js";
import { registerRedTeamToolkit } from "./tools/penetration/red_team_toolkit.js";
const server = new McpServer({
    name: "mcp-god-mode",
    version: "1.6.0",
}, {
    capabilities: {
        tools: {},
    },
});
// Register only the new tools
registerSiemToolkit(server);
registerCloudSecurityAssessment(server);
registerApiSecurityTesting(server);
registerEmailSecuritySuite(server);
registerDatabaseSecurityToolkit(server);
registerRedTeamToolkit(server);
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("MCP God Mode server running with new security tools");
}
main().catch((error) => {
    console.error("Server error:", error);
    process.exit(1);
});
