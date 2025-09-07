#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { spawn, exec } from "node:child_process";
import { promisify } from "node:util";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";

const execAsync = promisify(exec);

// Search engine configurations
const SEARCH_ENGINES = {
  google: {
    name: 'Google',
    url: 'https://www.google.com/search?q=',
    selectors: {
      input: 'input[name="q"]',
      results: '#search .g, .g',
      title: 'h3',
      link: 'a[href]',
      snippet: '.VwiC3b, .s3v9rd',
      next: 'a[aria-label="Next page"]'
    },
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
  },
  duckduckgo: {
    name: 'DuckDuckGo',
    url: 'https://duckduckgo.com/?q=',
    selectors: {
      input: 'input[name="q"]',
      results: '.result',
      title: '.result__title a',
      link: '.result__title a',
      snippet: '.result__snippet',
      next: '.result--more__btn'
    },
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
  },
  bing: {
    name: 'Bing',
    url: 'https://www.bing.com/search?q=',
    selectors: {
      input: 'input[name="q"]',
      results: '.b_algo',
      title: 'h2 a',
      link: 'h2 a',
      snippet: '.b_caption p',
      next: '.b_pag a[aria-label="Next page"]'
    },
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
  },
  yahoo: {
    name: 'Yahoo',
    url: 'https://search.yahoo.com/search?p=',
    selectors: {
      input: 'input[name="p"]',
      results: '.dd',
      title: 'h3 a',
      link: 'h3 a',
      snippet: '.compText',
      next: '.next'
    },
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
  }
};

// Specialized search sites
const SPECIALIZED_SEARCH = {
  reddit: {
    name: 'Reddit',
    url: 'https://www.reddit.com/search/?q=',
    selectors: {
      results: '[data-testid="post-container"]',
      title: 'h3',
      link: 'a[data-testid="post-title"]',
      snippet: '[data-testid="post-content"]',
      subreddit: '[data-testid="subreddit-name"]',
      author: '[data-testid="post_author_link"]',
      score: '[data-testid="vote-arrows"]'
    },
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
  },
  wikipedia: {
    name: 'Wikipedia',
    url: 'https://en.wikipedia.org/wiki/Special:Search?search=',
    selectors: {
      results: '.mw-search-result',
      title: '.mw-search-result-heading a',
      link: '.mw-search-result-heading a',
      snippet: '.searchresult',
      size: '.mw-search-result-data'
    },
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
  },
  github: {
    name: 'GitHub',
    url: 'https://github.com/search?q=',
    selectors: {
      results: '.repo-list-item, .search-title',
      title: '.repo-list-name a, .search-title a',
      link: '.repo-list-name a, .search-title a',
      snippet: '.repo-list-description, .search-snippet',
      language: '.repo-language-color',
      stars: '.octicon-star'
    },
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
  },
  stackoverflow: {
    name: 'Stack Overflow',
    url: 'https://stackoverflow.com/search?q=',
    selectors: {
      results: '.s-post-summary',
      title: '.s-post-summary--title a',
      link: '.s-post-summary--title a',
      snippet: '.s-post-summary--content',
      tags: '.s-post-summary--meta-tags a',
      votes: '.s-post-summary--stats-item-number'
    },
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
  },
  youtube: {
    name: 'YouTube',
    url: 'https://www.youtube.com/results?search_query=',
    selectors: {
      results: '#contents ytd-video-renderer',
      title: '#video-title',
      link: '#video-title',
      snippet: '#description-text',
      channel: '#channel-name a',
      views: '#metadata-line span:first-child',
      duration: '.ytd-thumbnail-overlay-time-status-renderer'
    },
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
  },
  amazon: {
    name: 'Amazon',
    url: 'https://www.amazon.com/s?k=',
    selectors: {
      results: '[data-component-type="s-search-result"]',
      title: 'h2 a span',
      link: 'h2 a',
      snippet: '.a-size-base-plus',
      price: '.a-price-whole',
      rating: '.a-icon-alt',
      image: '.s-image'
    },
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
  }
};

export function registerWebSearch(server: McpServer) {
  // Universal Web Search Tool
  server.registerTool("mcp_mcp-god-mode_web_search", {
    description: "Universal web search across multiple search engines and specialized sites including Google, DuckDuckGo, Reddit, Wikipedia, GitHub, Stack Overflow, YouTube, and Amazon",
    inputSchema: {
      query: z.string().describe("Search query to execute"),
      engine: z.enum(["google", "duckduckgo", "bing", "yahoo", "reddit", "wikipedia", "github", "stackoverflow", "youtube", "amazon"]).describe("Search engine or site to use"),
      max_results: z.number().min(1).max(100).default(10).describe("Maximum number of results to return"),
      include_snippets: z.boolean().default(true).describe("Whether to include result snippets"),
      include_metadata: z.boolean().default(false).describe("Whether to include additional metadata (ratings, dates, etc.)"),
      timeout: z.number().min(5000).max(120000).default(30000).describe("Timeout in milliseconds"),
      headless: z.boolean().default(true).describe("Run browser in headless mode")
    },
    outputSchema: {
      success: z.boolean(),
      results: z.array(z.object({
        title: z.string(),
        url: z.string(),
        snippet: z.string().optional(),
        metadata: z.record(z.string()).optional(),
        source: z.string()
      })).optional(),
      error: z.string().optional(),
      search_engine: z.string(),
      query: z.string(),
      result_count: z.number(),
      search_url: z.string().optional()
    }
  }, async ({ query, engine, max_results, include_snippets, include_metadata, timeout, headless }) => {
    try {
      const searchConfig = engine in SEARCH_ENGINES ? SEARCH_ENGINES[engine] : SPECIALIZED_SEARCH[engine];
      if (!searchConfig) {
        return {
          success: false,
          error: `Unsupported search engine: ${engine}`,
          search_engine: engine,
          query,
          result_count: 0
        };
      }

      const searchUrl = searchConfig.url + encodeURIComponent(query);
      const results = await performWebSearch(searchUrl, searchConfig, max_results, include_snippets, include_metadata, timeout, headless);

      return {
        success: true,
        results,
        search_engine: searchConfig.name,
        query,
        result_count: results.length,
        search_url: searchUrl
      };

    } catch (error) {
      return {
        success: false,
        error: `Search failed: ${error.message}`,
        search_engine: engine,
        query,
        result_count: 0
      };
    }
  });

  // Multi-Engine Search Tool
  server.registerTool("mcp_mcp-god-mode_multi_engine_search", {
    description: "Search across multiple engines simultaneously and compare results",
    inputSchema: {
      query: z.string().describe("Search query to execute"),
      engines: z.array(z.enum(["google", "duckduckgo", "bing", "yahoo", "reddit", "wikipedia", "github", "stackoverflow", "youtube", "amazon"])).min(2).max(5).describe("Search engines to use"),
      max_results_per_engine: z.number().min(1).max(20).default(5).describe("Maximum results per engine"),
      include_snippets: z.boolean().default(true).describe("Whether to include result snippets"),
      timeout: z.number().min(10000).max(180000).default(60000).describe("Timeout in milliseconds")
    },
    outputSchema: {
      success: z.boolean(),
      results: z.record(z.array(z.object({
        title: z.string(),
        url: z.string(),
        snippet: z.string().optional(),
        source: z.string()
      }))).optional(),
      error: z.string().optional(),
      query: z.string(),
      engines_used: z.array(z.string()),
      total_results: z.number()
    }
  }, async ({ query, engines, max_results_per_engine, include_snippets, timeout }) => {
    try {
      const results: Record<string, any[]> = {};
      let totalResults = 0;

      // Search each engine
      for (const engine of engines) {
        try {
          const searchConfig = engine in SEARCH_ENGINES ? SEARCH_ENGINES[engine] : SPECIALIZED_SEARCH[engine];
          if (searchConfig) {
            const searchUrl = searchConfig.url + encodeURIComponent(query);
            const engineResults = await performWebSearch(searchUrl, searchConfig, max_results_per_engine, include_snippets, false, timeout, true);
            results[engine] = engineResults;
            totalResults += engineResults.length;
          }
        } catch (error) {
          results[engine] = [];
          console.error(`Search failed for ${engine}:`, error.message);
        }
      }

      return {
        success: true,
        results,
        query,
        engines_used: engines,
        total_results: totalResults
      };

    } catch (error) {
      return {
        success: false,
        error: `Multi-engine search failed: ${error.message}`,
        query,
        engines_used: engines,
        total_results: 0
      };
    }
  });

  // Search Result Analysis Tool
  server.registerTool("mcp_mcp-god-mode_search_analysis", {
    description: "Analyze search results for trends, patterns, and insights",
    inputSchema: {
      results: z.array(z.object({
        title: z.string(),
        url: z.string(),
        snippet: z.string().optional(),
        source: z.string()
      })).describe("Search results to analyze"),
      analysis_type: z.enum(["trends", "domains", "keywords", "sentiment", "comprehensive"]).describe("Type of analysis to perform"),
      include_visualization: z.boolean().default(false).describe("Generate visualization data")
    },
    outputSchema: {
      success: z.boolean(),
      analysis: z.object({
        total_results: z.number(),
        unique_domains: z.number(),
        top_domains: z.array(z.object({
          domain: z.string(),
          count: z.number(),
          percentage: z.number()
        })),
        top_keywords: z.array(z.object({
          keyword: z.string(),
          count: z.number(),
          frequency: z.number()
        })),
        sentiment_analysis: z.object({
          positive: z.number(),
          negative: z.number(),
          neutral: z.number()
        }).optional(),
        trends: z.array(z.string()).optional(),
        visualization_data: z.record(z.any()).optional()
      }).optional(),
      error: z.string().optional()
    }
  }, async ({ results, analysis_type, include_visualization }) => {
    try {
      const analysis = await analyzeSearchResults(results, analysis_type, include_visualization);

      return {
        success: true,
        analysis
      };

    } catch (error) {
      return {
        success: false,
        error: `Search analysis failed: ${error.message}`
      };
    }
  });
}

// Helper functions
async function detectBrowserEngine(): Promise<string> {
  const engines = [
    { name: 'playwright', command: 'npx playwright --version' },
    { name: 'puppeteer', command: 'npx puppeteer --version' },
    { name: 'chrome', command: 'google-chrome --version || chromium --version || chrome --version' }
  ];

  for (const engine of engines) {
    try {
      await execAsync(engine.command);
      return engine.name;
    } catch (error) {
      continue;
    }
  }
  throw new Error("No browser engine available. Please install Playwright, Puppeteer, or Chrome.");
}

async function launchBrowser(engine: string, headless: boolean) {
  switch (engine) {
    case 'playwright':
      const { chromium } = await import('playwright');
      return await chromium.launch({ 
        headless,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });
      
    case 'puppeteer':
      const puppeteer = await import('puppeteer');
      return await puppeteer.launch({ 
        headless,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });
      
    case 'chrome':
      const { chromium: chrome } = await import('playwright');
      return await chrome.launch({ 
        headless,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });
      
    default:
      throw new Error(`Unsupported browser engine: ${engine}`);
  }
}

async function performWebSearch(url: string, config: any, maxResults: number, includeSnippets: boolean, includeMetadata: boolean, timeout: number, headless: boolean) {
  const engine = await detectBrowserEngine();
  const browser = await launchBrowser(engine, headless);
  
  try {
    const page = await browser.newPage();
    
    // Set headers
    if (config.headers) {
      await page.setExtraHTTPHeaders(config.headers);
    }
    
    // Navigate to search URL
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout });
    
    // Wait for results to load
    await (page as any).waitForSelector(config.selectors.results, { timeout: 10000 });
    
    // Extract results
    const results = await (page as any).evaluate((selectors: any, maxResults: number, includeSnippets: boolean, includeMetadata: boolean) => {
      const resultElements = document.querySelectorAll(selectors.results);
      const results = [];
      
      for (let i = 0; i < Math.min(resultElements.length, maxResults); i++) {
        const element = resultElements[i];
        const titleElement = element.querySelector(selectors.title);
        const linkElement = element.querySelector(selectors.link);
        const snippetElement = includeSnippets ? element.querySelector(selectors.snippet) : null;
        
        if (titleElement && linkElement) {
          const result: any = {
            title: titleElement.textContent?.trim() || '',
            url: linkElement.href || '',
            source: 'web_search'
          };
          
          if (snippetElement) {
            result.snippet = snippetElement.textContent?.trim() || '';
          }
          
          if (includeMetadata) {
            result.metadata = {};
            
            // Extract additional metadata based on available selectors
            if (selectors.subreddit) {
              const subredditElement = element.querySelector(selectors.subreddit);
              if (subredditElement) {
                result.metadata.subreddit = subredditElement.textContent?.trim();
              }
            }
            
            if (selectors.author) {
              const authorElement = element.querySelector(selectors.author);
              if (authorElement) {
                result.metadata.author = authorElement.textContent?.trim();
              }
            }
            
            if (selectors.score) {
              const scoreElement = element.querySelector(selectors.score);
              if (scoreElement) {
                result.metadata.score = scoreElement.textContent?.trim();
              }
            }
            
            if (selectors.language) {
              const languageElement = element.querySelector(selectors.language);
              if (languageElement) {
                result.metadata.language = languageElement.textContent?.trim();
              }
            }
            
            if (selectors.stars) {
              const starsElement = element.querySelector(selectors.stars);
              if (starsElement) {
                result.metadata.stars = starsElement.textContent?.trim();
              }
            }
            
            if (selectors.price) {
              const priceElement = element.querySelector(selectors.price);
              if (priceElement) {
                result.metadata.price = priceElement.textContent?.trim();
              }
            }
            
            if (selectors.rating) {
              const ratingElement = element.querySelector(selectors.rating);
              if (ratingElement) {
                result.metadata.rating = ratingElement.textContent?.trim();
              }
            }
          }
          
          results.push(result);
        }
      }
      
      return results;
    }, config.selectors, maxResults, includeSnippets, includeMetadata);
    
    return results;
  } finally {
    await browser.close();
  }
}

async function analyzeSearchResults(results: any[], analysisType: string, includeVisualization: boolean) {
  const analysis: any = {
    total_results: results.length,
    unique_domains: 0,
    top_domains: [],
    top_keywords: [],
    sentiment_analysis: undefined,
    trends: undefined,
    visualization_data: undefined
  };

  // Extract domains
  const domainCounts: Record<string, number> = {};
  const allText = results.map(r => `${r.title} ${r.snippet || ''}`).join(' ').toLowerCase();
  
  results.forEach(result => {
    try {
      const domain = new URL(result.url).hostname;
      domainCounts[domain] = (domainCounts[domain] || 0) + 1;
    } catch (error) {
      // Invalid URL, skip
    }
  });

  analysis.unique_domains = Object.keys(domainCounts).length;
  analysis.top_domains = Object.entries(domainCounts)
    .map(([domain, count]) => ({
      domain,
      count,
      percentage: (count / results.length) * 100
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  // Extract keywords
  const words = allText
    .replace(/[^\w\s]/g, ' ')
    .split(/\s+/)
    .filter(word => word.length > 3)
    .filter(word => !['this', 'that', 'with', 'from', 'they', 'been', 'have', 'were', 'said', 'each', 'which', 'their', 'time', 'will', 'about', 'there', 'could', 'other', 'after', 'first', 'well', 'also', 'where', 'much', 'some', 'very', 'when', 'come', 'here', 'just', 'like', 'long', 'make', 'many', 'over', 'such', 'take', 'than', 'them', 'these', 'think', 'want', 'been', 'good', 'great', 'little', 'new', 'old', 'right', 'small', 'large', 'high', 'low', 'big', 'long', 'short', 'wide', 'narrow', 'thick', 'thin', 'heavy', 'light', 'fast', 'slow', 'hot', 'cold', 'warm', 'cool', 'dry', 'wet', 'clean', 'dirty', 'full', 'empty', 'open', 'closed', 'safe', 'dangerous', 'easy', 'hard', 'simple', 'complex', 'cheap', 'expensive', 'free', 'paid', 'public', 'private', 'local', 'remote', 'online', 'offline'].includes(word.toLowerCase()));

  const wordCounts: Record<string, number> = {};
  words.forEach(word => {
    wordCounts[word] = (wordCounts[word] || 0) + 1;
  });

  analysis.top_keywords = Object.entries(wordCounts)
    .map(([keyword, count]) => ({
      keyword,
      count,
      frequency: count / words.length
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);

  // Sentiment analysis (basic)
  if (analysisType === 'sentiment' || analysisType === 'comprehensive') {
    const positiveWords = ['good', 'great', 'excellent', 'amazing', 'wonderful', 'fantastic', 'awesome', 'brilliant', 'outstanding', 'perfect', 'best', 'love', 'like', 'enjoy', 'happy', 'pleased', 'satisfied', 'recommend', 'helpful', 'useful', 'effective', 'efficient', 'reliable', 'quality', 'professional'];
    const negativeWords = ['bad', 'terrible', 'awful', 'horrible', 'worst', 'hate', 'dislike', 'angry', 'frustrated', 'disappointed', 'useless', 'broken', 'slow', 'expensive', 'cheap', 'poor', 'unreliable', 'difficult', 'hard', 'complicated', 'confusing', 'annoying', 'boring', 'waste', 'problem', 'issue', 'error', 'bug', 'fail', 'broken'];

    let positiveCount = 0;
    let negativeCount = 0;
    let neutralCount = 0;

    words.forEach(word => {
      if (positiveWords.includes(word)) {
        positiveCount++;
      } else if (negativeWords.includes(word)) {
        negativeCount++;
      } else {
        neutralCount++;
      }
    });

    const total = positiveCount + negativeCount + neutralCount;
    analysis.sentiment_analysis = {
      positive: total > 0 ? (positiveCount / total) * 100 : 0,
      negative: total > 0 ? (negativeCount / total) * 100 : 0,
      neutral: total > 0 ? (neutralCount / total) * 100 : 0
    };
  }

  // Trends analysis
  if (analysisType === 'trends' || analysisType === 'comprehensive') {
    analysis.trends = [
      `Most common domain: ${analysis.top_domains[0]?.domain || 'N/A'}`,
      `Top keyword: ${analysis.top_keywords[0]?.keyword || 'N/A'}`,
      `Average results per domain: ${(results.length / analysis.unique_domains).toFixed(2)}`,
      `Content diversity: ${analysis.unique_domains > 5 ? 'High' : analysis.unique_domains > 2 ? 'Medium' : 'Low'}`
    ];
  }

  // Visualization data
  if (includeVisualization) {
    analysis.visualization_data = {
      domain_distribution: analysis.top_domains.slice(0, 10),
      keyword_frequency: analysis.top_keywords.slice(0, 15),
      sentiment_pie: analysis.sentiment_analysis,
      result_metrics: {
        total_results: analysis.total_results,
        unique_domains: analysis.unique_domains,
        average_keywords_per_result: (words.length / results.length).toFixed(2)
      }
    };
  }

  return analysis;
}
