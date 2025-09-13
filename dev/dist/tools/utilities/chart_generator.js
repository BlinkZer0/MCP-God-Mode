import { z } from "zod";
import * as fs from "node:fs/promises";
export function registerChartGenerator(server) {
    server.registerTool("chart_generator", {
        description: "Advanced SVG chart and graph generation with animations from data",
        inputSchema: {
            chart_type: z.enum(["line", "bar", "pie", "scatter", "histogram", "donut", "area", "radar"]).describe("Type of chart to generate"),
            data: z.array(z.object({
                label: z.string(),
                value: z.number().describe("Data value for the chart")
            })).describe("Data for chart generation"),
            title: z.string().optional().describe("Chart title"),
            x_label: z.string().optional().describe("X-axis label"),
            y_label: z.string().optional().describe("Y-axis label"),
            output_format: z.enum(["svg", "png", "jpg", "pdf"]).optional().default("svg").describe("Output format (defaults to SVG)"),
            animated: z.boolean().optional().default(true).describe("Enable animations (defaults to true)"),
            colors: z.array(z.string()).optional().describe("Custom color palette"),
            width: z.number().optional().default(800).describe("Chart width in pixels"),
            height: z.number().optional().default(600).describe("Chart height in pixels"),
            theme: z.enum(["light", "dark", "colorful", "minimal"]).optional().default("colorful").describe("Chart theme")
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
                }).optional(),
                animated: z.boolean().optional(),
                theme: z.string().optional(),
                format: z.string().optional()
            }).optional()
        }
    }, async ({ chart_type, data, title, x_label, y_label, output_format, animated, colors, width, height, theme }) => {
        try {
            // Set defaults
            const format = output_format || 'svg';
            const isAnimated = animated !== false; // Default to true
            const chartWidth = width || 800;
            const chartHeight = height || 600;
            const chartTheme = theme || 'colorful';
            // Generate SVG chart
            const svgContent = generateSVGChart({
                type: chart_type,
                data,
                title: title || `${chart_type.charAt(0).toUpperCase() + chart_type.slice(1)} Chart`,
                xLabel: x_label,
                yLabel: y_label,
                width: chartWidth,
                height: chartHeight,
                animated: isAnimated,
                colors: colors || getThemeColors(chartTheme),
                theme: chartTheme
            });
            // Save chart file
            const chartPath = `./chart_${Date.now()}.${format}`;
            await fs.writeFile(chartPath, svgContent, 'utf-8');
            const chartData = {
                type: chart_type,
                data_points: data.length,
                dimensions: {
                    width: chartWidth,
                    height: chartHeight
                },
                animated: isAnimated,
                theme: chartTheme,
                format: format
            };
            return {
                content: [],
                structuredContent: {
                    success: true,
                    message: `${chart_type} ${format.toUpperCase()} chart generated successfully with ${data.length} data points${isAnimated ? ' (animated)' : ''}`,
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
// Helper function to get theme colors
function getThemeColors(theme) {
    const themes = {
        light: ['#3498db', '#e74c3c', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c', '#34495e', '#e67e22'],
        dark: ['#2c3e50', '#c0392b', '#27ae60', '#d35400', '#8e44ad', '#16a085', '#2c3e50', '#e67e22'],
        colorful: ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD', '#98D8C8', '#F7DC6F'],
        minimal: ['#2C3E50', '#34495E', '#7F8C8D', '#95A5A6', '#BDC3C7', '#ECF0F1', '#E74C3C', '#F39C12']
    };
    return themes[theme] || themes.colorful;
}
// Main SVG chart generation function
function generateSVGChart(options) {
    const { type, data, title, xLabel, yLabel, width, height, animated, colors, theme } = options;
    // Calculate chart dimensions
    const margin = { top: 60, right: 40, bottom: 80, left: 80 };
    const chartWidth = width - margin.left - margin.right;
    const chartHeight = height - margin.top - margin.bottom;
    // Generate animations
    const animations = animated ? generateAnimations() : '';
    // Generate chart content based on type
    let chartContent = '';
    switch (type) {
        case 'pie':
        case 'donut':
            chartContent = generatePieChart(data, chartWidth, chartHeight, colors, animated);
            break;
        case 'bar':
            chartContent = generateBarChart(data, chartWidth, chartHeight, colors, animated);
            break;
        case 'line':
            chartContent = generateLineChart(data, chartWidth, chartHeight, colors, animated);
            break;
        case 'area':
            chartContent = generateAreaChart(data, chartWidth, chartHeight, colors, animated);
            break;
        case 'scatter':
            chartContent = generateScatterChart(data, chartWidth, chartHeight, colors, animated);
            break;
        case 'histogram':
            chartContent = generateHistogramChart(data, chartWidth, chartHeight, colors, animated);
            break;
        case 'radar':
            chartContent = generateRadarChart(data, chartWidth, chartHeight, colors, animated);
            break;
        default:
            chartContent = generateBarChart(data, chartWidth, chartHeight, colors, animated);
    }
    return `<?xml version="1.0" encoding="UTF-8"?>
<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <style>
      .title { font-family: 'Segoe UI', Arial, sans-serif; font-size: 24px; font-weight: bold; fill: ${theme === 'dark' ? '#fff' : '#333'}; }
      .label { font-family: 'Segoe UI', Arial, sans-serif; font-size: 14px; fill: ${theme === 'dark' ? '#ccc' : '#666'}; }
      .value { font-family: 'Segoe UI', Arial, sans-serif; font-size: 16px; font-weight: bold; fill: ${theme === 'dark' ? '#fff' : '#333'}; }
      .axis { stroke: ${theme === 'dark' ? '#555' : '#ccc'}; stroke-width: 1; }
      .grid { stroke: ${theme === 'dark' ? '#333' : '#f0f0f0'}; stroke-width: 1; }
      .bar { fill-opacity: 0.8; }
      .pie-slice { stroke: ${theme === 'dark' ? '#222' : '#fff'}; stroke-width: 2; }
      ${animations}
    </style>
  </defs>
  
  <!-- Background -->
  <rect width="${width}" height="${height}" fill="${theme === 'dark' ? '#1a1a1a' : '#ffffff'}" />
  
  <!-- Title -->
  <text x="${width / 2}" y="30" text-anchor="middle" class="title">${title}</text>
  
  <!-- Chart Content -->
  <g transform="translate(${margin.left}, ${margin.top})">
    ${chartContent}
  </g>
  
  <!-- Axis Labels -->
  ${xLabel ? `<text x="${width / 2}" y="${height - 20}" text-anchor="middle" class="label">${xLabel}</text>` : ''}
  ${yLabel ? `<text x="20" y="${height / 2}" text-anchor="middle" class="label" transform="rotate(-90, 20, ${height / 2})">${yLabel}</text>` : ''}
  
  <!-- Legend -->
  ${generateLegend(data, colors, width - 200, 50, theme)}
</svg>`;
}
// Animation generation
function generateAnimations() {
    return `
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    @keyframes slideUp {
      from { transform: translateY(20px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }
    @keyframes scaleIn {
      from { transform: scale(0); }
      to { transform: scale(1); }
    }
    .animate-fade { animation: fadeIn 0.6s ease-out; }
    .animate-slide { animation: slideUp 0.8s ease-out; }
    .animate-scale { animation: scaleIn 0.5s ease-out; }
  `;
}
// Pie chart generation
function generatePieChart(data, width, height, colors, animated) {
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) / 2 - 20;
    const total = data.reduce((sum, item) => sum + item.value, 0);
    let currentAngle = 0;
    return data.map((item, index) => {
        const percentage = item.value / total;
        const angle = percentage * 360;
        const startAngle = currentAngle;
        const endAngle = currentAngle + angle;
        const x1 = centerX + radius * Math.cos((startAngle - 90) * Math.PI / 180);
        const y1 = centerY + radius * Math.sin((startAngle - 90) * Math.PI / 180);
        const x2 = centerX + radius * Math.cos((endAngle - 90) * Math.PI / 180);
        const y2 = centerY + radius * Math.sin((endAngle - 90) * Math.PI / 180);
        const largeArcFlag = angle > 180 ? 1 : 0;
        const pathData = `M ${centerX} ${centerY} L ${x1} ${y1} A ${radius} ${radius} 0 ${largeArcFlag} 1 ${x2} ${y2} Z`;
        currentAngle += angle;
        return `<path d="${pathData}" fill="${colors[index % colors.length]}" class="pie-slice ${animated ? 'animate-scale' : ''}" style="animation-delay: ${index * 0.1}s" />`;
    }).join('');
}
// Bar chart generation
function generateBarChart(data, width, height, colors, animated) {
    const maxValue = Math.max(...data.map(d => d.value));
    const barWidth = width / data.length * 0.8;
    const barSpacing = width / data.length * 0.2;
    return data.map((item, index) => {
        const barHeight = (item.value / maxValue) * height * 0.8;
        const x = index * (barWidth + barSpacing) + barSpacing / 2;
        const y = height - barHeight;
        return `
      <rect x="${x}" y="${y}" width="${barWidth}" height="${barHeight}" 
            fill="${colors[index % colors.length]}" class="bar ${animated ? 'animate-slide' : ''}" 
            style="animation-delay: ${index * 0.1}s" />
      <text x="${x + barWidth / 2}" y="${y - 5}" text-anchor="middle" class="value">${item.value}</text>
    `;
    }).join('');
}
// Line chart generation
function generateLineChart(data, width, height, colors, animated) {
    const maxValue = Math.max(...data.map(d => d.value));
    const minValue = Math.min(...data.map(d => d.value));
    const valueRange = maxValue - minValue;
    const points = data.map((item, index) => {
        const x = (index / (data.length - 1)) * width;
        const y = height - ((item.value - minValue) / valueRange) * height;
        return `${x},${y}`;
    }).join(' ');
    const pathData = `M ${points.split(' ')[0]} L ${points.split(' ').slice(1).join(' L ')}`;
    return `
    <polyline points="${points}" fill="none" stroke="${colors[0]}" stroke-width="3" 
              class="${animated ? 'animate-fade' : ''}" />
    ${data.map((item, index) => {
        const x = (index / (data.length - 1)) * width;
        const y = height - ((item.value - minValue) / valueRange) * height;
        return `<circle cx="${x}" cy="${y}" r="4" fill="${colors[0]}" class="${animated ? 'animate-scale' : ''}" style="animation-delay: ${index * 0.1}s" />`;
    }).join('')}
  `;
}
// Area chart generation
function generateAreaChart(data, width, height, colors, animated) {
    const maxValue = Math.max(...data.map(d => d.value));
    const minValue = Math.min(...data.map(d => d.value));
    const valueRange = maxValue - minValue;
    const points = data.map((item, index) => {
        const x = (index / (data.length - 1)) * width;
        const y = height - ((item.value - minValue) / valueRange) * height;
        return `${x},${y}`;
    }).join(' ');
    const pathData = `M 0,${height} L ${points} L ${width},${height} Z`;
    return `<path d="${pathData}" fill="${colors[0]}" fill-opacity="0.3" stroke="${colors[0]}" stroke-width="2" class="${animated ? 'animate-fade' : ''}" />`;
}
// Scatter chart generation
function generateScatterChart(data, width, height, colors, animated) {
    const maxValue = Math.max(...data.map(d => d.value));
    const minValue = Math.min(...data.map(d => d.value));
    const valueRange = maxValue - minValue;
    return data.map((item, index) => {
        const x = (index / (data.length - 1)) * width;
        const y = height - ((item.value - minValue) / valueRange) * height;
        return `<circle cx="${x}" cy="${y}" r="6" fill="${colors[index % colors.length]}" class="${animated ? 'animate-scale' : ''}" style="animation-delay: ${index * 0.1}s" />`;
    }).join('');
}
// Histogram chart generation
function generateHistogramChart(data, width, height, colors, animated) {
    // Group data into bins for histogram
    const bins = 10;
    const maxValue = Math.max(...data.map(d => d.value));
    const binSize = maxValue / bins;
    const histogram = new Array(bins).fill(0);
    data.forEach(item => {
        const binIndex = Math.min(Math.floor(item.value / binSize), bins - 1);
        histogram[binIndex]++;
    });
    const maxCount = Math.max(...histogram);
    const barWidth = width / bins * 0.8;
    const barSpacing = width / bins * 0.2;
    return histogram.map((count, index) => {
        const barHeight = (count / maxCount) * height * 0.8;
        const x = index * (barWidth + barSpacing) + barSpacing / 2;
        const y = height - barHeight;
        return `
      <rect x="${x}" y="${y}" width="${barWidth}" height="${barHeight}" 
            fill="${colors[index % colors.length]}" class="bar ${animated ? 'animate-slide' : ''}" 
            style="animation-delay: ${index * 0.1}s" />
      <text x="${x + barWidth / 2}" y="${y - 5}" text-anchor="middle" class="value">${count}</text>
    `;
    }).join('');
}
// Radar chart generation
function generateRadarChart(data, width, height, colors, animated) {
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) / 2 - 40;
    const maxValue = Math.max(...data.map(d => d.value));
    const points = data.map((item, index) => {
        const angle = (index / data.length) * 2 * Math.PI - Math.PI / 2;
        const distance = (item.value / maxValue) * radius;
        const x = centerX + distance * Math.cos(angle);
        const y = centerY + distance * Math.sin(angle);
        return `${x},${y}`;
    }).join(' ');
    return `
    <polygon points="${points}" fill="${colors[0]}" fill-opacity="0.3" stroke="${colors[0]}" stroke-width="2" class="${animated ? 'animate-fade' : ''}" />
    ${data.map((item, index) => {
        const angle = (index / data.length) * 2 * Math.PI - Math.PI / 2;
        const distance = (item.value / maxValue) * radius;
        const x = centerX + distance * Math.cos(angle);
        const y = centerY + distance * Math.sin(angle);
        return `<circle cx="${x}" cy="${y}" r="4" fill="${colors[0]}" class="${animated ? 'animate-scale' : ''}" style="animation-delay: ${index * 0.1}s" />`;
    }).join('')}
  `;
}
// Legend generation
function generateLegend(data, colors, x, y, theme) {
    return `
    <g transform="translate(${x}, ${y})">
      ${data.map((item, index) => `
        <rect x="0" y="${index * 25}" width="15" height="15" fill="${colors[index % colors.length]}" />
        <text x="20" y="${index * 25 + 12}" class="label">${item.label}: ${item.value}</text>
      `).join('')}
    </g>
  `;
}
