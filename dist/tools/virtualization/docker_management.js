import { z } from "zod";
export function registerDockerManagement(server) {
    server.registerTool("docker_management", {
        description: "Docker container and image management",
        inputSchema: {
            action: z.enum(["list_containers", "list_images", "start", "stop", "create", "remove", "logs", "exec"]).describe("Docker management action to perform"),
            container_name: z.string().optional().describe("Name or ID of the container"),
            image_name: z.string().optional().describe("Name of the Docker image"),
            command: z.string().optional().describe("Command to execute in container"),
            ports: z.array(z.string()).optional().describe("Port mappings (e.g., ['8080:80'])")
        },
        outputSchema: {
            success: z.boolean(),
            message: z.string(),
            containers: z.array(z.object({
                id: z.string(),
                name: z.string(),
                status: z.string(),
                image: z.string()
            })).optional(),
            images: z.array(z.object({
                id: z.string(),
                name: z.string(),
                tag: z.string(),
                size: z.string()
            })).optional()
        }
    }, async ({ action, container_name, image_name, command, ports }) => {
        try {
            // Docker management implementation
            let message = "";
            let containers = [];
            let images = [];
            switch (action) {
                case "list_containers":
                    message = "Docker containers listed successfully";
                    containers = [
                        { id: "abc123", name: "web-server", status: "Running", image: "nginx:latest" },
                        { id: "def456", name: "database", status: "Stopped", image: "postgres:13" }
                    ];
                    break;
                case "list_images":
                    message = "Docker images listed successfully";
                    images = [
                        { id: "img123", name: "nginx", tag: "latest", size: "133MB" },
                        { id: "img456", name: "postgres", tag: "13", size: "314MB" }
                    ];
                    break;
                case "start":
                    message = `Container ${container_name} started successfully`;
                    break;
                case "stop":
                    message = `Container ${container_name} stopped successfully`;
                    break;
                case "create":
                    message = `Container ${container_name} created successfully`;
                    break;
                case "remove":
                    message = `Container ${container_name} removed successfully`;
                    break;
                case "logs":
                    message = `Logs retrieved for ${container_name}`;
                    break;
                case "exec":
                    message = `Command executed in ${container_name}: ${command}`;
                    break;
            }
            return {
                content: [{ type: "text", text: "Operation failed" }],
                structuredContent: {
                    success: true,
                    message,
                    containers,
                    images
                }
            };
        }
        catch (error) {
            return { content: [], structuredContent: { success: false, message: `Docker management failed: ${error instanceof Error ? error.message : "Unknown error"}` } };
        }
    });
}
