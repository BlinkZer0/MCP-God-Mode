# Competitive Intelligence Tool

## Overview

The Competitive Intelligence Tool is a comprehensive MCP (Model Context Protocol) tool for gathering and analyzing competitive intelligence from competitor websites. This tool is based on the original [Competitive Intelligence CLI](https://github.com/qb-harshit/Competitve-Intelligence-CLI) by Harshit Jain (@qb-harshit) and has been enhanced with natural language interface capabilities and MCP integration.

## Attribution

**Original Creator:** Harshit Jain (@qb-harshit)  
**Original Repository:** https://github.com/qb-harshit/Competitve-Intelligence-CLI  
**License:** Open Source  
**Enhancement:** This MCP tool extends the original CLI with natural language interface and MCP protocol integration.

## Features

### 🌍 Cross-Platform Support
- **Windows, Linux, macOS** - Full desktop support
- **Android, iOS** - Mobile-optimized with extended timeouts
- **Mobile-specific data directories** - App-appropriate storage locations
- **Platform-aware user agents** - Optimized headers for each platform
- **Secure path handling** - Cross-platform safe file operations

### 🕷️ Web Scraping
- Extract clean content from homepages and feature pages
- Remove HTML/CSS clutter while preserving meaningful text
- Automatic content cleaning and structure preservation
- **Mobile-optimized timeouts** - Extended timeouts for mobile networks
- **Enhanced error handling** - Platform-specific error messages

### 🗺️ Sitemap Analysis
- Automatically find and scrape feature-related pages
- Intelligent URL categorization (features, pricing, products, customers, FAQ, API)
- Filter pages by category and keywords

### 🧹 Content Processing
- Clean HTML extraction with metadata preservation
- Word count and content analysis
- Structured data organization

### 🔍 Analysis Engine
- Custom analysis prompts for competitive insights
- Feature extraction and analysis
- Pricing information identification
- Customer story and case study extraction
- API and technical documentation analysis

### 📊 Report Generation
- Comprehensive markdown reports
- Chronological analysis tracking
- Professional formatting with timestamps

### 💾 Data Management
- Organized JSON storage per company
- Persistent data across sessions
- Easy data retrieval and management

### 🗣️ Natural Language Interface
- Process commands in natural language
- Intuitive command interpretation
- Suggested actions and guidance

## Available Tools

### 1. `competitive_intelligence`
Main tool for competitive intelligence operations.

**Actions:**
- `addCompany` - Add a new company to track
- `removeCompany` - Remove a company and all its data
- `scrapeHomepage` - Extract homepage content
- `analyzeSitemap` - Find and scrape feature pages
- `runAnalysis` - Execute custom analysis prompts
- `viewData` - View company data and analysis results
- `listCompanies` - List all tracked companies
- `generateReport` - Generate comprehensive analysis report

### 2. `competitive_intelligence_nl`
Natural language interface for intuitive command processing.

**Example Commands:**
- "Add company Stripe"
- "Remove company Stripe" or "Delete company Stripe"
- "Scrape homepage for Stripe https://stripe.com"
- "Analyze sitemap for Stripe https://stripe.com/sitemap.xml"
- "Analyze features for Stripe"
- "Analyze pricing for Stripe"
- "List all companies"
- "View data for Stripe"
- "Generate report for Stripe"

### 3. `competitive_intelligence_test`
Configuration test tool with attribution information.

## Usage Examples

### Adding a Company
```json
{
  "action": "addCompany",
  "companyName": "Stripe"
}
```

### Removing a Company
```json
{
  "action": "removeCompany",
  "companyName": "Stripe"
}
```

### Scraping Homepage
```json
{
  "action": "scrapeHomepage",
  "companyName": "Stripe",
  "homepageUrl": "https://stripe.com"
}
```

### Analyzing Sitemap
```json
{
  "action": "analyzeSitemap",
  "companyName": "Stripe",
  "sitemapUrl": "https://stripe.com/sitemap.xml",
  "keywords": ["api", "features", "pricing"],
  "categories": ["features", "pricing", "products"]
}
```

### Running Analysis
```json
{
  "action": "runAnalysis",
  "companyName": "Stripe",
  "prompt": "Extract all features and their descriptions",
  "dataSource": "all"
}
```

### Natural Language Commands
```json
{
  "command": "Add company Stripe and scrape their homepage at https://stripe.com"
}
```

## Data Storage

### Cross-Platform Data Locations
- **Windows/Linux/macOS:** `./data/companies/[company_name]_data.json`
- **Android:** `/storage/emulated/0/Download/competitive_intelligence/companies/`
- **iOS:** `~/Documents/competitive_intelligence/companies/`

### JSON Files
- **Location:** Platform-specific data directory
- **Contains:** All scraped content, metadata, analysis results
- **Format:** Consolidated JSON per company
- **Security:** All paths validated and sanitized

### Markdown Reports
- **Location:** Platform-specific data directory
- **Contains:** All analysis results in chronological order
- **Format:** Professional markdown with timestamps
- **Security:** Paths validated against allowed roots

## URL Categorization

The system automatically categorizes URLs based on keywords:

- **Features:** `feature`, `capability`, `function`
- **Products:** `product`, `service`, `solution`
- **Pricing:** `pricing`, `price`, `cost`, `plan`
- **Customers:** `customer`, `customers`, `case-study`, `success-story`, `testimonial`
- **FAQ:** `faq`, `support`, `help-center`, `knowledge-base`
- **API:** `api`, `developer`, `docs`, `documentation`
- **Other:** Everything else

## Analysis Prompts

### Feature Analysis
```
Extract all features and their descriptions from the content
```

### Pricing Analysis
```
Find pricing information and plans
```

### Customer Analysis
```
Extract customer success stories and case studies
```

### Technical Analysis
```
List all API endpoints and technical capabilities mentioned
```

### Business Analysis
```
Identify competitive advantages and market positioning
```

## Content Quality

The system automatically:
- ✅ Removes HTML/CSS clutter
- ✅ Preserves all essential content
- ✅ Maintains text structure
- ✅ Filters out navigation elements
- ✅ Keeps meaningful sentences

**Typical content extraction:** 70,000+ characters of clean text per homepage

## Workflow Example

1. **Add Company:** "Stripe"
2. **Scrape Homepage:** "https://stripe.com"
3. **Analyze Sitemap:** "https://stripe.com/sitemap.xml" with keywords "api,features,pricing,customers,faq"
4. **Run Analysis:**
   - "Extract all features and their descriptions"
   - "Find pricing information and plans"
   - "Extract customer success stories and case studies"
   - "Identify competitive advantages"
5. **Review Report:** Check generated markdown report

## Technical Implementation

### Dependencies
- Node.js built-in modules (fs, path, os, child_process)
- Zod for schema validation
- Fetch API for web requests
- MCP SDK for protocol integration
- Cross-platform environment detection

### Architecture
- Modular design with separate functions for each operation
- Cross-platform error handling and validation
- Platform-aware data storage with JSON format
- Natural language processing for command interpretation
- Mobile-optimized network requests and timeouts

### Cross-Platform Features
- **Platform Detection:** Automatic detection of Windows, Linux, macOS, Android, iOS
- **Mobile Optimization:** Extended timeouts, mobile-specific user agents
- **Secure Paths:** All file operations validated against allowed roots
- **Data Directories:** Platform-appropriate storage locations
- **Error Handling:** Platform-specific error messages and recovery

### Security Considerations
- Input validation and sanitization across all platforms
- Cross-platform safe file path handling
- Error boundary protection with platform awareness
- Rate limiting considerations for web scraping
- Mobile-specific security considerations

## Contributing

This tool is based on the original Competitive Intelligence CLI. For enhancements or modifications:

1. Maintain attribution to the original creator
2. Follow the existing code structure and patterns
3. Add comprehensive error handling
4. Include natural language interface support
5. Ensure cross-platform compatibility

## License

This tool maintains the same open-source license as the original Competitive Intelligence CLI. Please refer to the original repository for specific licensing terms.

## Support

For issues or questions:
1. Check the original repository: https://github.com/qb-harshit/Competitve-Intelligence-CLI
2. Verify all dependencies are installed
3. Ensure URLs are accessible and properly formatted
4. Check file permissions for data directory

---

**Ready to start competitive intelligence gathering!** 🚀

*Enhanced with natural language interface and MCP integration while maintaining full compatibility with the original tool's functionality.*
