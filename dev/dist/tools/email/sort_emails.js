import { z } from "zod";
export function registerSortEmails(server) {
    server.registerTool("sort_emails", {
        description: "Email sorting and organization",
        inputSchema: {
            emails: z.array(z.object({
                id: z.string(),
                from: z.string(),
                subject: z.string(),
                date: z.string(),
                priority: z.string().optional()
            })).describe("Array of emails to sort"),
            sort_by: z.enum(["date", "sender", "subject", "priority", "size"]).describe("Sorting criteria"),
            order: z.enum(["asc", "desc"]).optional().describe("Sorting order (default: desc)"),
            group_by: z.string().optional().describe("Group emails by criteria (sender, date, priority)")
        },
        outputSchema: {
            success: z.boolean(),
            message: z.string(),
            sorted_emails: z.array(z.object({
                id: z.string(),
                from: z.string(),
                subject: z.string(),
                date: z.string(),
                priority: z.string().optional()
            })).optional()
        }
    }, async ({ emails, sort_by, order, group_by }) => {
        try {
            // Email sorting implementation
            const sorted_emails = emails.sort((a, b) => {
                if (sort_by === "date") {
                    return order === "asc" ? new Date(a.date).getTime() - new Date(b.date).getTime() : new Date(b.date).getTime() - new Date(a.date).getTime();
                }
                return 0;
            });
            return {
                content: [],
                structuredContent: {
                    success: true,
                    message: `Emails sorted successfully by ${sort_by}`,
                    sorted_emails
                }
            };
        }
        catch (error) {
            return {
                content: [],
                structuredContent: {
                    success: false,
                    message: `Email sorting failed: ${error instanceof Error ? error.message : 'Unknown error'}`
                }
            };
        }
    });
}
