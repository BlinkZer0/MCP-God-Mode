# Web Search Tool

## Overview

The Web Search Tool provides comprehensive search capabilities across multiple search engines and specialized sites. It offers both single-engine and multi-engine search functionality with advanced result analysis and filtering options.

## Features

### Supported Search Engines

#### General Search Engines
- **Google**: World's most popular search engine
- **DuckDuckGo**: Privacy-focused search engine
- **Bing**: Microsoft's search engine
- **Yahoo**: Yahoo search engine

#### Specialized Search Sites
- **Reddit**: Social media and community discussions
- **Wikipedia**: Encyclopedia and knowledge base
- **GitHub**: Code repositories and development resources
- **Stack Overflow**: Programming Q&A and technical discussions
- **YouTube**: Video content and tutorials
- **Amazon**: Product search and reviews

### Advanced Features
- **Multi-Engine Search**: Search across multiple engines simultaneously
- **Result Analysis**: Analyze search results for trends and patterns
- **Metadata Extraction**: Extract additional information from results
- **Custom Filtering**: Filter results by various criteria
- **Snippet Generation**: Generate contextual snippets for results

## Tools

### 1. Universal Web Search (`mcp_mcp-god-mode_web_search`)

Search across multiple search engines and specialized sites.

**Parameters:**
- `query` (string): Search query to execute
- `engine` (enum): Search engine to use
  - Options: google, duckduckgo, bing, yahoo, reddit, wikipedia, github, stackoverflow, youtube, amazon
- `max_results` (number): Maximum results to return (1-100, default: 10)
- `include_snippets` (boolean): Include result snippets (default: true)
- `include_metadata` (boolean): Include additional metadata (default: false)
- `timeout` (number): Timeout in milliseconds (5000-120000, default: 30000)
- `headless` (boolean): Run browser in headless mode (default: true)

**Output:**
- `success` (boolean): Operation success status
- `results` (array): Search results with title, URL, snippet, metadata
- `search_engine` (string): Name of search engine used
- `query` (string): Original search query
- `result_count` (number): Number of results returned
- `search_url` (string): Generated search URL

**Example:**
```javascript
const result = await webSearch({
  query: "artificial intelligence machine learning",
  engine: "google",
  max_results: 15,
  include_snippets: true,
  include_metadata: true
});
```

### 2. Multi-Engine Search (`mcp_mcp-god-mode_multi_engine_search`)

Search across multiple engines simultaneously and compare results.

**Parameters:**
- `query` (string): Search query to execute
- `engines` (array): Search engines to use (2-5 engines)
- `max_results_per_engine` (number): Maximum results per engine (1-20, default: 5)
- `include_snippets` (boolean): Include result snippets (default: true)
- `timeout` (number): Timeout in milliseconds (10000-180000, default: 60000)

**Output:**
- `success` (boolean): Operation success status
- `results` (object): Results organized by engine
- `query` (string): Original search query
- `engines_used` (array): List of engines used
- `total_results` (number): Total results across all engines

**Example:**
```javascript
const result = await multiEngineSearch({
  query: "cybersecurity best practices",
  engines: ["google", "duckduckgo", "bing"],
  max_results_per_engine: 8,
  include_snippets: true
});
```

### 3. Search Result Analysis (`mcp_mcp-god-mode_search_analysis`)

Analyze search results for trends, patterns, and insights.

**Parameters:**
- `results` (array): Search results to analyze
- `analysis_type` (enum): Type of analysis to perform
  - Options: trends, domains, keywords, sentiment, comprehensive
- `include_visualization` (boolean): Generate visualization data (default: false)

**Output:**
- `success` (boolean): Operation success status
- `analysis` (object): Analysis results including:
  - `total_results` (number): Total number of results
  - `unique_domains` (number): Number of unique domains
  - `top_domains` (array): Most common domains with counts
  - `top_keywords` (array): Most frequent keywords
  - `sentiment_analysis` (object): Sentiment breakdown
  - `trends` (array): Identified trends
  - `visualization_data` (object): Data for visualization

**Example:**
```javascript
const analysis = await searchAnalysis({
  results: searchResults,
  analysis_type: "comprehensive",
  include_visualization: true
});
```

## Search Engine Specific Features

### Google
- **Rich Snippets**: Enhanced result display with ratings, dates, images
- **Knowledge Graph**: Direct answers and entity information
- **Related Searches**: Suggested related queries
- **Search Operators**: Support for advanced search syntax

### DuckDuckGo
- **Privacy Focus**: No tracking or personalization
- **Instant Answers**: Direct answers for common queries
- **Bangs**: Quick access to other sites (!wikipedia, !github)
- **No Filter Bubble**: Unbiased search results

### Reddit
- **Community Discussions**: Real user experiences and opinions
- **Subreddit Filtering**: Search within specific communities
- **Post Types**: Links, text posts, images, videos
- **Voting System**: Community-curated content quality

### Wikipedia
- **Encyclopedic Content**: Comprehensive, factual information
- **Cross-References**: Links to related articles
- **Categories**: Hierarchical topic organization
- **Multilingual**: Support for multiple languages

### GitHub
- **Code Repositories**: Source code and documentation
- **Language Filtering**: Search by programming language
- **Stars and Forks**: Community engagement metrics
- **Issues and Pull Requests**: Development discussions

### Stack Overflow
- **Technical Q&A**: Programming and technical questions
- **Tag System**: Categorized by technology and topic
- **Voting System**: Community-verified answers
- **Code Examples**: Practical code snippets

### YouTube
- **Video Content**: Tutorials, reviews, entertainment
- **Duration Filtering**: Short videos, long-form content
- **Channel Information**: Creator details and subscriber counts
- **View Counts**: Popularity metrics

### Amazon
- **Product Search**: Physical and digital products
- **Price Information**: Current pricing and availability
- **Reviews and Ratings**: Customer feedback
- **Product Categories**: Organized by type and brand


## Natural Language Access
Users can request web search operations using natural language:
- "Search the web"
- "Find web information"
- "Query search engines"
- "Search online content"
- "Look up web data"
## Usage Examples

### Basic Search
```javascript
// Simple Google search
const googleResults = await webSearch({
  query: "python programming tutorial",
  engine: "google",
  max_results: 10
});

// Reddit search for discussions
const redditResults = await webSearch({
  query: "best programming languages 2024",
  engine: "reddit",
  max_results: 15,
  include_metadata: true
});
```

### Technical Research
```javascript
// GitHub search for repositories
const githubResults = await webSearch({
  query: "machine learning framework",
  engine: "github",
  max_results: 20,
  include_metadata: true
});

// Stack Overflow for technical questions
const stackResults = await webSearch({
  query: "react hooks best practices",
  engine: "stackoverflow",
  max_results: 12
});
```

### Multi-Engine Comparison
```javascript
// Compare results across multiple engines
const comparison = await multiEngineSearch({
  query: "artificial intelligence ethics",
  engines: ["google", "duckduckgo", "bing", "wikipedia"],
  max_results_per_engine: 5
});

// Analyze the results
const analysis = await searchAnalysis({
  results: Object.values(comparison.results).flat(),
  analysis_type: "comprehensive",
  include_visualization: true
});
```

### Academic Research
```javascript
// Wikipedia for background information
const wikiResults = await webSearch({
  query: "quantum computing principles",
  engine: "wikipedia",
  max_results: 8
});

// YouTube for educational content
const videoResults = await webSearch({
  query: "quantum computing explained",
  engine: "youtube",
  max_results: 10,
  include_metadata: true
});
```

## Advanced Features

### Search Query Optimization
- **Boolean Operators**: AND, OR, NOT support
- **Phrase Search**: Exact phrase matching with quotes
- **Wildcards**: Partial word matching with asterisks
- **Exclusions**: Remove unwanted terms with minus sign

### Result Filtering
- **Date Range**: Filter by publication date
- **Domain Filtering**: Include or exclude specific domains
- **Content Type**: Filter by content type (text, images, videos)
- **Language**: Filter by language

### Metadata Extraction
- **Publication Dates**: Extract when content was published
- **Author Information**: Identify content creators
- **View Counts**: Popularity metrics for videos
- **Ratings**: User ratings and reviews
- **Categories**: Content categorization

### Sentiment Analysis
- **Positive/Negative**: Overall sentiment classification
- **Emotion Detection**: Identify emotional tone
- **Topic Sentiment**: Sentiment by specific topics
- **Trend Analysis**: Sentiment changes over time

## Performance Optimization

### Caching
- **Result Caching**: Cache search results for repeated queries
- **Engine Caching**: Cache engine-specific configurations
- **Metadata Caching**: Cache extracted metadata

### Rate Limiting
- **Request Throttling**: Limit requests per engine
- **Backoff Strategies**: Implement exponential backoff
- **Queue Management**: Manage concurrent requests

### Error Handling
- **Engine Fallback**: Fallback to alternative engines
- **Retry Logic**: Automatic retry for failed requests
- **Graceful Degradation**: Continue with partial results

## Security Considerations

### Privacy
- **No Tracking**: Avoid tracking user searches
- **Data Minimization**: Collect only necessary data
- **Secure Storage**: Encrypt cached results
- **User Consent**: Obtain consent for data collection

### Rate Limiting
- **Respect Limits**: Honor engine rate limits
- **Fair Use**: Avoid excessive requests
- **Terms of Service**: Comply with engine ToS
- **Attribution**: Properly attribute sources

### Content Filtering
- **Safe Search**: Enable safe search filters
- **Content Moderation**: Filter inappropriate content
- **Legal Compliance**: Comply with local laws
- **Ethical Use**: Use for legitimate purposes only

## Integration Examples

### With AI Tools
```javascript
// Search for information and feed to AI
const searchResults = await webSearch({
  query: "latest AI developments",
  engine: "google",
  max_results: 10
});

const aiResponse = await aiSiteInteraction({
  site: "chat.openai.com",
  action: "send_message",
  message: `Based on these search results: ${JSON.stringify(searchResults.results)}`
});
```

### With Form Completion
```javascript
// Search for information to fill forms
const companyInfo = await webSearch({
  query: "company contact information",
  engine: "google",
  max_results: 5
});

const formResult = await formCompletion({
  url: "https://example.com/contact",
  form_data: {
    company: companyInfo.results[0].title,
    website: companyInfo.results[0].url
  }
});
```

### With CAPTCHA Solving
```javascript
// Search for CAPTCHA solving techniques
const captchaInfo = await webSearch({
  query: "CAPTCHA solving methods",
  engine: "stackoverflow",
  max_results: 8
});

const captchaResult = await captchaDefeating({
  url: "https://example.com/form",
  captcha_type: "auto",
  method: "ocr"
});
```

## Troubleshooting

### Common Issues

1. **No Results Returned**
   - Check query syntax
   - Verify engine availability
   - Increase timeout value
   - Try different search terms

2. **Rate Limiting**
   - Implement delays between requests
   - Use different engines
   - Reduce request frequency
   - Check engine status

3. **Incomplete Results**
   - Increase max_results parameter
   - Check for dynamic content loading
   - Verify selectors are correct
   - Try different engines

4. **Metadata Extraction Fails**
   - Check if metadata is available
   - Verify selectors for metadata fields
   - Try different engines
   - Enable include_metadata parameter

### Performance Issues

1. **Slow Search Results**
   - Use headless mode
   - Reduce max_results
   - Optimize selectors
   - Use faster engines

2. **High Memory Usage**
   - Limit concurrent searches
   - Clear result caches
   - Use streaming results
   - Optimize data structures

3. **Browser Crashes**
   - Update browser engines
   - Reduce timeout values
   - Use stable selectors
   - Implement error recovery

## Future Enhancements

- **AI-Powered Search**: Intelligent query understanding
- **Real-Time Results**: Live search result updates
- **Voice Search**: Speech-to-text search capabilities
- **Image Search**: Visual search capabilities
- **Semantic Search**: Understanding search intent
- **Personalization**: User-specific result ranking
- **Collaborative Filtering**: Community-based recommendations

## Support and Resources

### Documentation
- Engine-specific documentation
- API reference guides
- Best practices guides
- Troubleshooting guides

### Community
- User forums and discussions
- Feature request tracking
- Bug report system
- Developer community

### Updates
- Regular feature updates
- Security patches
- Performance improvements
- New engine support

The Web Search Tool provides powerful, flexible search capabilities across multiple engines and specialized sites, making it an essential component of the MCP God Mode toolkit for research, analysis, and information gathering.
