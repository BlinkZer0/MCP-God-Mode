# Chart Generator Tool

## Overview
The **Chart Generator Tool** is a comprehensive chart and graph generation utility that provides advanced data visualization, chart creation, and graphical representation capabilities. It offers cross-platform support and enterprise-grade chart generation features.

## Features
- **Chart Types**: Multiple chart types including line, bar, pie, scatter, histogram, donut, area, and radar charts
- **Data Visualization**: Advanced data visualization and graphical representation
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Export Options**: Multiple export formats including SVG, PNG, JPG, and PDF
- **Customization**: Extensive chart customization and styling options
- **Animations**: Animated charts and interactive visualizations

## Usage

### Chart Creation
```bash
# Create line chart
{
  "chart_type": "line",
  "data": [
    {"label": "Jan", "value": 100},
    {"label": "Feb", "value": 150},
    {"label": "Mar", "value": 200}
  ],
  "title": "Monthly Sales"
}

# Create bar chart
{
  "chart_type": "bar",
  "data": [
    {"label": "Product A", "value": 300},
    {"label": "Product B", "value": 250},
    {"label": "Product C", "value": 400}
  ],
  "title": "Product Sales"
}
```

### Chart Customization
```bash
# Customized pie chart
{
  "chart_type": "pie",
  "data": [
    {"label": "Desktop", "value": 45},
    {"label": "Mobile", "value": 35},
    {"label": "Tablet", "value": 20}
  ],
  "title": "Device Usage",
  "colors": ["#FF6384", "#36A2EB", "#FFCE56"],
  "animated": true
}

# Scatter plot
{
  "chart_type": "scatter",
  "data": [
    {"label": "Point 1", "value": 25},
    {"label": "Point 2", "value": 50},
    {"label": "Point 3", "value": 75}
  ],
  "title": "Data Distribution",
  "x_label": "X Axis",
  "y_label": "Y Axis"
}
```

### Export Options
```bash
# Export as SVG
{
  "chart_type": "line",
  "data": [{"label": "Data", "value": 100}],
  "output_format": "svg",
  "width": 800,
  "height": 600
}

# Export as PNG
{
  "chart_type": "bar",
  "data": [{"label": "Data", "value": 100}],
  "output_format": "png",
  "width": 800,
  "height": 600
}
```

## Parameters

### Chart Parameters
- **chart_type**: Type of chart to generate (line, bar, pie, scatter, histogram, donut, area, radar)
- **data**: Data for chart generation
- **title**: Chart title
- **x_label**: X-axis label
- **y_label**: Y-axis label

### Customization Parameters
- **colors**: Custom color palette
- **width**: Chart width in pixels
- **height**: Chart height in pixels
- **theme**: Chart theme (light, dark, colorful, minimal)
- **animated**: Enable animations

### Export Parameters
- **output_format**: Output format (svg, png, jpg, pdf)
- **width**: Chart width in pixels
- **height**: Chart height in pixels

## Output Format
```json
{
  "success": true,
  "chart_type": "line",
  "result": {
    "chart_url": "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iODAwIiBoZWlnaHQ9IjYwMCI...",
    "chart_path": "./chart.svg",
    "width": 800,
    "height": 600,
    "format": "svg"
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows chart generation
- **Linux**: Complete functionality with Linux chart generation
- **macOS**: Full feature support with macOS chart generation
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Line Chart
```bash
# Create line chart
{
  "chart_type": "line",
  "data": [
    {"label": "Jan", "value": 100},
    {"label": "Feb", "value": 150},
    {"label": "Mar", "value": 200}
  ],
  "title": "Monthly Sales"
}

# Result
{
  "success": true,
  "result": {
    "chart_type": "line",
    "chart_url": "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iODAwIiBoZWlnaHQ9IjYwMCI...",
    "width": 800,
    "height": 600
  }
}
```

### Example 2: Bar Chart
```bash
# Create bar chart
{
  "chart_type": "bar",
  "data": [
    {"label": "Product A", "value": 300},
    {"label": "Product B", "value": 250},
    {"label": "Product C", "value": 400}
  ],
  "title": "Product Sales"
}

# Result
{
  "success": true,
  "result": {
    "chart_type": "bar",
    "chart_url": "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iODAwIiBoZWlnaHQ9IjYwMCI...",
    "width": 800,
    "height": 600
  }
}
```

### Example 3: Pie Chart
```bash
# Create pie chart
{
  "chart_type": "pie",
  "data": [
    {"label": "Desktop", "value": 45},
    {"label": "Mobile", "value": 35},
    {"label": "Tablet", "value": 20}
  ],
  "title": "Device Usage",
  "colors": ["#FF6384", "#36A2EB", "#FFCE56"]
}

# Result
{
  "success": true,
  "result": {
    "chart_type": "pie",
    "chart_url": "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iODAwIiBoZWlnaHQ9IjYwMCI...",
    "width": 800,
    "height": 600
  }
}
```

## Error Handling
- **Data Errors**: Proper handling of invalid or missing data
- **Format Errors**: Secure handling of unsupported chart formats
- **Export Errors**: Robust error handling for export failures
- **Customization Errors**: Safe handling of customization parameter issues

## Related Tools
- **Data Analysis**: Data analysis and visualization tools
- **Reporting**: Report generation and documentation tools
- **Visualization**: Advanced data visualization tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Chart Generator Tool, please refer to the main MCP God Mode documentation or contact the development team.
