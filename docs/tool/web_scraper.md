# 🌐 Web Scraper Tool - MCP God Mode

## Overview
The **Web Scraper Tool** (`mcp_mcp-god-mode_web_scraper`) is an advanced web scraping utility that provides comprehensive data extraction capabilities across Windows, Linux, macOS, Android, and iOS platforms. It supports CSS selector-based data extraction, multiple output formats, link following, and respectful scraping practices with configurable delays and custom headers.

## Functionality
- **Web Scraping**: Extract data from web pages using CSS selectors
- **Data Extraction**: Targeted extraction of specific content and elements
- **Link Following**: Crawl multiple pages with configurable depth
- **Output Formats**: Support for JSON, CSV, text, and HTML output
- **Cross-Platform Support**: Native implementation across all supported operating systems
- **Advanced Features**: Respectful scraping, custom headers, and comprehensive error handling

## Technical Details

### Tool Identifier
- **MCP Tool Name**: `mcp_mcp-god-mode_web_scraper`
- **Category**: Web & Data Extraction
- **Platform Support**: Windows, Linux, macOS, Android, iOS
- **Elevated Permissions**: Not required for web scraping operations

### Input Parameters
```typescript
{
  url: string,             // URL of the web page to scrape
  action: "scrape_page" | "extract_data" | "follow_links" | "scrape_table" | "extract_images" | "get_metadata",
  selector?: string,       // CSS selector to target specific elements
  output_format?: "json" | "csv" | "text" | "html", // Output format
  follow_links?: boolean,  // Whether to follow links and scrape multiple pages
  max_pages?: number,      // Maximum number of pages to scrape
  delay?: number,          // Delay between requests in milliseconds
  headers?: object         // Custom HTTP headers to send with requests
}
```

### Output Response
```typescript
{
  url: string,             // Original URL scraped
  action: string,          // Action performed
  status: "success" | "error" | "partial",
  timestamp: string,       // Scraping timestamp
  results: {
    // Page Content Results
    content?: {
      title: string,       // Page title
      description: string, // Page description
      text_content: string, // Extracted text content
      html_content: string, // Raw HTML content
      word_count: number,  // Word count of extracted content
      character_count: number // Character count of extracted content
    },
    
    // Extracted Data Results
    extracted_data?: Array<{
      selector: string,    // CSS selector used
      element_type: string, // Type of element (div, p, span, etc.)
      text_content: string, // Text content of element
      attributes: object,  // Element attributes
      position: number     // Position of element on page
    }>,
    
    // Table Results
    tables?: Array<{
      table_index: number, // Index of table on page
      headers: string[],   // Table headers
      rows: string[][],    // Table rows
      row_count: number,   // Number of rows
      column_count: number // Number of columns
    }>,
    
    // Image Results
    images?: Array<{
      src: string,         // Image source URL
      alt: string,         // Image alt text
      title: string,       // Image title
      dimensions: {
        width: number,     // Image width
        height: number     // Image height
      },
      file_size?: number   // Image file size in bytes
    }>,
    
    // Link Results
    links?: Array<{
      href: string,        // Link URL
      text: string,        // Link text
      title: string,       // Link title
      target: string,      // Link target
      rel: string         // Link relationship
    }>,
    
    // Metadata Results
    metadata?: {
      title: string,       // Page title
      description: string, // Meta description
      keywords: string[],  // Meta keywords
      author: string,      // Page author
      language: string,    // Page language
      robots: string,      // Robots meta tag
      og_tags: object,    // Open Graph tags
      twitter_tags: object // Twitter Card tags
    },
    
    // Scraping Statistics
    statistics: {
      pages_scraped: number,    // Number of pages scraped
      elements_found: number,   // Number of elements found
      links_followed: number,   // Number of links followed
      total_size: number,       // Total content size in bytes
      scraping_time: number     // Total scraping time in milliseconds
    }
  },
  error?: string,          // Error message if scraping failed
  warnings?: string[],     // Warning messages
  execution_time?: number  // Total execution time in milliseconds
}
```


## Natural Language Access
Users can request web scraper operations using natural language:
- "Scrape web content"
- "Extract web data"
- "Collect web information"
- "Gather web content"
- "Harvest web data"
## Usage Examples

### Basic Page Scraping
```typescript
const basicScrape = await web_scraper({
  url: "https://example.com",
  action: "scrape_page",
  output_format: "json"
});

if (basicScrape.status === "success") {
  const content = basicScrape.results?.content;
  console.log(`Page Title: ${content?.title}`);
  console.log(`Word Count: ${content?.word_count}`);
  console.log(`Content: ${content?.text_content?.substring(0, 200)}...`);
}
```

### Targeted Data Extraction
```typescript
const dataExtraction = await web_scraper({
  url: "https://news.example.com",
  action: "extract_data",
  selector: "h1, h2, .article-title, .article-content",
  output_format: "json"
});

if (dataExtraction.status === "success") {
  const extractedData = dataExtraction.results?.extracted_data;
  console.log("Extracted Elements:");
  extractedData?.forEach((element, index) => {
    console.log(`${index + 1}. ${element.element_type}: ${element.text_content}`);
  });
}
```

### Table Scraping
```typescript
const tableScrape = await web_scraper({
  url: "https://data.example.com/table",
  action: "scrape_table",
  output_format: "csv"
});

if (tableScrape.status === "success") {
  const tables = tableScrape.results?.tables;
  tables?.forEach((table, index) => {
    console.log(`Table ${index + 1}: ${table.row_count} rows, ${table.column_count} columns`);
    console.log("Headers:", table.headers.join(", "));
    table.rows.slice(0, 3).forEach(row => {
      console.log("Row:", row.join(", "));
    });
  });
}
```

### Image Extraction
```typescript
const imageExtraction = await web_scraper({
  url: "https://gallery.example.com",
  action: "extract_images",
  output_format: "json"
});

if (imageExtraction.status === "success") {
  const images = imageExtraction.results?.images;
  console.log("Images Found:");
  images?.forEach((image, index) => {
    console.log(`${index + 1}. ${image.src}`);
    console.log(`   Alt: ${image.alt}`);
    console.log(`   Dimensions: ${image.dimensions.width}x${image.dimensions.height}`);
  });
}
```

### Link Following and Crawling
```typescript
const linkCrawling = await web_scraper({
  url: "https://blog.example.com",
  action: "follow_links",
  selector: "a[href*='/article/']",
  follow_links: true,
  max_pages: 5,
  delay: 2000,
  output_format: "json"
});

if (linkCrawling.status === "success") {
  const stats = linkCrawling.results?.statistics;
  console.log(`Scraping completed: ${stats?.pages_scraped} pages`);
  console.log(`Elements found: ${stats?.elements_found}`);
  console.log(`Links followed: ${stats?.links_followed}`);
  console.log(`Total time: ${stats?.scraping_time}ms`);
}
```

## Integration Points

### Server Integration
- **Full Server**: ✅ Included
- **Modular Server**: ❌ Not included
- **Minimal Server**: ✅ Included
- **Ultra-Minimal Server**: ✅ Included

### Dependencies
- Native HTTP client libraries
- HTML parsing engines
- CSS selector processors
- Data format converters

## Platform-Specific Features

### Windows
- **Windows Networking**: Windows networking stack optimization
- **Internet Explorer**: IE compatibility features
- **Windows Security**: Windows security framework integration
- **Performance Optimization**: Windows-specific optimizations

### Linux
- **Unix Networking**: Native Unix networking support
- **Open Source Libraries**: Open source web scraping tools
- **Performance Tuning**: Linux performance tuning
- **Resource Management**: Unix resource management

### macOS
- **macOS Networking**: macOS network framework
- **Safari Integration**: Safari compatibility features
- **Security Framework**: macOS security framework
- **Performance Optimization**: macOS-specific optimizations

### Mobile Platforms
- **Mobile Networking**: Mobile-optimized networking
- **Touch Optimization**: Touch-optimized scraping
- **Battery Optimization**: Battery-efficient scraping
- **Permission Handling**: Mobile permission management

## Web Scraping Features

### Content Extraction
- **Text Extraction**: Clean text content extraction
- **HTML Extraction**: Raw HTML content extraction
- **Structured Data**: Structured data extraction
- **Metadata Extraction**: Page metadata extraction

### Element Selection
- **CSS Selectors**: Advanced CSS selector support
- **XPath Support**: XPath expression support
- **Element Filtering**: Element filtering and validation
- **Position Selection**: Element position-based selection

### Data Processing
- **Content Cleaning**: Automatic content cleaning
- **Data Validation**: Data validation and verification
- **Format Conversion**: Multiple output format support
- **Data Structuring**: Structured data organization

## Security Features

### Scraping Security
- **Rate Limiting**: Configurable rate limiting
- **User Agent Rotation**: User agent rotation and management
- **Header Customization**: Custom HTTP header support
- **Cookie Management**: Session cookie handling

### Access Control
- **Authentication Support**: Basic and token authentication
- **Session Management**: Session state management
- **Access Validation**: Access permission validation
- **Security Auditing**: Scraping activity auditing

## Error Handling

### Common Issues
- **Network Errors**: Connection and timeout issues
- **Access Denied**: Website access restrictions
- **Content Changes**: Website structure changes
- **Rate Limiting**: Website rate limiting

### Recovery Actions
- Automatic retry mechanisms
- Alternative scraping methods
- Fallback content extraction
- Comprehensive error reporting

## Performance Characteristics

### Scraping Speed
- **Single Page**: 1-5 seconds for basic pages
- **Complex Pages**: 5-15 seconds for complex pages
- **Multiple Pages**: Variable based on page count and delay
- **Large Content**: 10-60 seconds for large content pages

### Resource Usage
- **CPU**: Low to moderate (5-30% during scraping)
- **Memory**: Variable (10-200MB based on content size)
- **Network**: High during active scraping
- **Disk**: Low (temporary storage only)

## Monitoring and Logging

### Scraping Monitoring
- **Progress Tracking**: Scraping progress monitoring
- **Performance Metrics**: Scraping performance tracking
- **Error Analysis**: Scraping error analysis
- **Success Tracking**: Successful scraping tracking

### Data Monitoring
- **Content Analysis**: Content analysis and validation
- **Data Quality**: Data quality monitoring
- **Extraction Efficiency**: Extraction efficiency tracking
- **Output Validation**: Output format validation

## Troubleshooting

### Scraping Issues
1. Verify URL accessibility
2. Check network connectivity
3. Review CSS selectors
4. Confirm website structure

### Performance Issues
1. Optimize CSS selectors
2. Reduce page count limits
3. Increase delay between requests
4. Monitor system resources

## Best Practices

### Implementation
- Use appropriate CSS selectors
- Implement proper error handling
- Respect website robots.txt
- Monitor scraping performance

### Ethics and Compliance
- Respect website terms of service
- Implement appropriate delays
- Use respectful user agents
- Monitor for policy violations

## Related Tools
- **Browser Control**: Browser automation and control
- **Network Diagnostics**: Network connectivity testing
- **File Operations**: Data storage and management
- **Data Processing**: Data analysis and processing

## Version History
- **v1.0**: Initial implementation
- **v1.1**: Enhanced scraping features
- **v1.2**: Advanced data extraction
- **v1.3**: Cross-platform improvements
- **v1.4a**: Professional web scraping features

---

**⚠️ IMPORTANT: Always respect website terms of service and robots.txt when scraping. Implement appropriate delays and use respectful scraping practices.**

*This document is part of MCP God Mode v1.4a - Advanced AI Agent Toolkit*
