# Competitive Intelligence Tool

## Overview
The **Competitive Intelligence Tool** is a comprehensive competitor analysis utility that provides advanced competitive intelligence gathering, analysis, and reporting capabilities. It offers cross-platform support and enterprise-grade competitive intelligence features.

## Features
- **Company Management**: Advanced company and competitor management
- **Web Scraping**: Comprehensive web scraping and data extraction
- **Sitemap Analysis**: Advanced sitemap analysis and content discovery
- **Cross-Platform**: Windows, Linux, macOS, Android, iOS support
- **Data Analysis**: Competitive data analysis and insights generation
- **Reporting**: Detailed competitive intelligence reports and dashboards

## Usage

### Company Management
```bash
# Add company
{
  "action": "addCompany",
  "companyName": "Stripe",
  "homepageUrl": "https://stripe.com"
}

# Remove company
{
  "action": "removeCompany",
  "companyName": "Stripe"
}

# List companies
{
  "action": "listCompanies"
}
```

### Web Scraping
```bash
# Scrape homepage
{
  "action": "scrapeHomepage",
  "companyName": "Stripe",
  "homepageUrl": "https://stripe.com"
}

# Analyze sitemap
{
  "action": "analyzeSitemap",
  "companyName": "Stripe",
  "sitemapUrl": "https://stripe.com/sitemap.xml"
}
```

### Data Analysis
```bash
# Run analysis
{
  "action": "runAnalysis",
  "companyName": "Stripe",
  "prompt": "Analyze Stripe's pricing strategy",
  "dataSource": "homepage"
}

# View data
{
  "action": "viewData",
  "companyName": "Stripe"
}

# Generate report
{
  "action": "generateReport",
  "companyName": "Stripe"
}
```

## Parameters

### Company Parameters
- **action**: Competitive intelligence action to perform
- **companyName**: Company name for the operation
- **homepageUrl**: Homepage URL to scrape
- **sitemapUrl**: Sitemap URL to analyze

### Analysis Parameters
- **keywords**: Keywords for sitemap filtering
- **categories**: Categories to include (features, pricing, products, customers, faq, api, all)
- **prompt**: Analysis prompt
- **dataSource**: Data source for analysis (homepage, all, or page:URL)

### Scraping Parameters
- **timeout**: Timeout for scraping operations
- **max_pages**: Maximum pages to scrape
- **include_images**: Whether to include images in scraping

## Output Format
```json
{
  "success": true,
  "action": "addCompany",
  "result": {
    "companyName": "Stripe",
    "homepageUrl": "https://stripe.com",
    "status": "added",
    "company_id": "stripe_001"
  }
}
```

## Cross-Platform Support
- **Windows**: Full support with Windows competitive intelligence
- **Linux**: Complete functionality with Linux competitive intelligence
- **macOS**: Full feature support with macOS competitive intelligence
- **Android**: Mobile-optimized interface
- **iOS**: Native iOS integration

## Examples

### Example 1: Add Company
```bash
# Add company
{
  "action": "addCompany",
  "companyName": "Stripe",
  "homepageUrl": "https://stripe.com"
}

# Result
{
  "success": true,
  "result": {
    "companyName": "Stripe",
    "homepageUrl": "https://stripe.com",
    "status": "added"
  }
}
```

### Example 2: Scrape Homepage
```bash
# Scrape homepage
{
  "action": "scrapeHomepage",
  "companyName": "Stripe",
  "homepageUrl": "https://stripe.com"
}

# Result
{
  "success": true,
  "result": {
    "companyName": "Stripe",
    "homepageUrl": "https://stripe.com",
    "scraped_data": {
      "title": "Stripe - Online Payment Processing",
      "description": "Stripe is a technology company that builds economic infrastructure for the internet.",
      "features": ["Payment processing", "Billing", "Connect"]
    }
  }
}
```

### Example 3: Run Analysis
```bash
# Run analysis
{
  "action": "runAnalysis",
  "companyName": "Stripe",
  "prompt": "Analyze Stripe's pricing strategy",
  "dataSource": "homepage"
}

# Result
{
  "success": true,
  "result": {
    "companyName": "Stripe",
    "analysis": {
      "pricing_strategy": "Transaction-based pricing",
      "key_features": ["Payment processing", "Billing", "Connect"],
      "target_market": "Online businesses and developers"
    }
  }
}
```

## Error Handling
- **Scraping Errors**: Proper handling of web scraping failures
- **Analysis Errors**: Secure handling of data analysis failures
- **Timeout Errors**: Robust error handling for operation timeouts
- **Data Errors**: Safe handling of data processing problems

## Related Tools
- **Web Scraping**: Web scraping and data extraction tools
- **Data Analysis**: Data analysis and insights generation tools
- **Business Intelligence**: Business intelligence and reporting tools

## Version
- **Current Version**: 1.0.0
- **Last Updated**: September 2025
- **Compatibility**: MCP God Mode v1.9+

## Support
For issues or questions about the Competitive Intelligence Tool, please refer to the main MCP God Mode documentation or contact the development team.
