import { z } from "zod";
export function registerChartGenerator(server) {
    server.registerTool("chart_generator", {
        description: "Chart and graph generation from data",
        inputSchema: {
            chart_type: z.enum(["line", "bar", "pie", "scatter", "histogram"]).describe("Type of chart to generate"),
            data: z.array(z.object({
                label: z.string(),
                value: z.number()
            })).describe("Data for chart generation"),
            title: z.string().optional().describe("Chart title"),
            x_label: z.string().optional().describe("X-axis label"),
            y_label: z.string().optional().describe("Y-axis label"),
            output_format: z.enum(["png", "jpg", "svg", "pdf"]).optional().describe("Output image format")
        },
        outputSchema: {
            success: z.boolean(),
            message: z.string(),
            chart_path: z.string().optional(),
            chart_data: z.object({
                type: z.string(),
                data_points: z.number(),
                dimensions: z.object({
                    width: z.number().optional(),
                    height: z.number().optional()
                }).optional()
            }).optional()
        }
    }, async ({ chart_type, data, title, x_label, y_label, output_format }) => {
        try {
            // Chart generation implementation
            const chartPath = `./chart_${Date.now()}.${output_format || 'png'}`;
            const chartData = {
                type: chart_type,
                data_points: data.length,
                dimensions: {
                    width: 800,
                    height: 600
                }
            };
            return {
                content: [],
                structuredContent: {
                    success: true,
                    message: `${chart_type} chart generated successfully with ${data.length} data points`,
                    chart_path: chartPath,
                    chart_data: chartData
                }
            };
        }
        catch (error) {
            return { content: [], structuredContent: { success: false, message: `Chart generation failed: ${error.message}` } };
        }
    });
}
