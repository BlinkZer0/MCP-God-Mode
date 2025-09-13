/**
 * Web Search Adapter
 *
 * Generic web search interface for finding official reporting sites
 * with configurable search providers and result filtering.
 */
export class WebSearchAdapter {
    apiKey;
    provider;
    constructor(provider = 'mock', apiKey) {
        this.provider = provider;
        this.apiKey = apiKey;
    }
    /**
     * Search for official reporting sites
     */
    async search(query, options = {}) {
        const { maxResults = 10, siteFilter, language = 'en', region = 'US' } = options;
        switch (this.provider) {
            case 'google':
                return this.searchGoogle(query, { maxResults, siteFilter, language, region });
            case 'bing':
                return this.searchBing(query, { maxResults, siteFilter, language, region });
            case 'duckduckgo':
                return this.searchDuckDuckGo(query, { maxResults, siteFilter, language, region });
            case 'mock':
                return this.searchMock(query, { maxResults, siteFilter, language, region });
            default:
                throw new Error(`Unsupported search provider: ${this.provider}`);
        }
    }
    /**
     * Google Custom Search API
     */
    async searchGoogle(query, options) {
        if (!this.apiKey) {
            throw new Error('Google API key required for Google search');
        }
        const searchEngineId = 'YOUR_SEARCH_ENGINE_ID'; // Configure this
        let searchQuery = query;
        if (options.siteFilter) {
            searchQuery += ` site:${options.siteFilter}`;
        }
        const url = new URL('https://www.googleapis.com/customsearch/v1');
        url.searchParams.set('key', this.apiKey);
        url.searchParams.set('cx', searchEngineId);
        url.searchParams.set('q', searchQuery);
        url.searchParams.set('num', String(options.maxResults || 10));
        url.searchParams.set('lr', `lang_${options.language}`);
        url.searchParams.set('cr', `country${options.region}`);
        try {
            const response = await fetch(url.toString());
            const data = await response.json();
            return (data.items || []).map((item, index) => ({
                url: item.link,
                title: item.title,
                snippet: item.snippet,
                domain: new URL(item.link).hostname,
                rank: index + 1
            }));
        }
        catch (error) {
            console.error('Google search error:', error);
            return [];
        }
    }
    /**
     * Bing Search API
     */
    async searchBing(query, options) {
        if (!this.apiKey) {
            throw new Error('Bing API key required for Bing search');
        }
        let searchQuery = query;
        if (options.siteFilter) {
            searchQuery += ` site:${options.siteFilter}`;
        }
        const url = new URL('https://api.bing.microsoft.com/v7.0/search');
        url.searchParams.set('q', searchQuery);
        url.searchParams.set('count', String(options.maxResults || 10));
        url.searchParams.set('mkt', `${options.language}-${options.region}`);
        try {
            const response = await fetch(url.toString(), {
                headers: {
                    'Ocp-Apim-Subscription-Key': this.apiKey
                }
            });
            const data = await response.json();
            return (data.webPages?.value || []).map((item, index) => ({
                url: item.url,
                title: item.name,
                snippet: item.snippet,
                domain: new URL(item.url).hostname,
                rank: index + 1
            }));
        }
        catch (error) {
            console.error('Bing search error:', error);
            return [];
        }
    }
    /**
     * DuckDuckGo Instant Answer API (limited but free)
     */
    async searchDuckDuckGo(query, options) {
        // DuckDuckGo doesn't have a traditional search API, but we can use their HTML
        // This is a simplified implementation - in practice you'd need to scrape
        const url = new URL('https://html.duckduckgo.com/html/');
        url.searchParams.set('q', query);
        if (options.siteFilter) {
            url.searchParams.set('q', `${query} site:${options.siteFilter}`);
        }
        try {
            const response = await fetch(url.toString(), {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (compatible; CrimeReporter/1.0)'
                }
            });
            const html = await response.text();
            // Parse HTML results (simplified - you'd want a proper HTML parser)
            return this.parseDuckDuckGoResults(html, options.maxResults || 10);
        }
        catch (error) {
            console.error('DuckDuckGo search error:', error);
            return [];
        }
    }
    /**
     * Mock search for testing and development
     */
    async searchMock(query, options) {
        // Return mock results for testing
        const mockResults = [
            {
                url: 'https://www.minneapolis.gov/police/report-crime',
                title: 'Minneapolis Police Department - Online Crime Reporting',
                snippet: 'Report crimes online through the official Minneapolis Police Department portal. Submit reports for theft, vandalism, and other non-emergency crimes.',
                domain: 'minneapolis.gov',
                rank: 1
            },
            {
                url: 'https://www.hennepin.us/sheriff/report-crime',
                title: 'Hennepin County Sheriff - Crime Reporting',
                snippet: 'Hennepin County Sheriff\'s Office online crime reporting system. File reports for incidents within Hennepin County jurisdiction.',
                domain: 'hennepin.us',
                rank: 2
            },
            {
                url: 'https://www.ic3.gov/Home/FileComplaint',
                title: 'FBI Internet Crime Complaint Center (IC3)',
                snippet: 'Report cybercrime, internet fraud, and online scams to the FBI Internet Crime Complaint Center.',
                domain: 'ic3.gov',
                rank: 3
            }
        ];
        // Filter by site if specified
        if (options.siteFilter) {
            return mockResults.filter(result => result.domain.includes(options.siteFilter) ||
                result.url.includes(options.siteFilter));
        }
        return mockResults.slice(0, options.maxResults || 10);
    }
    /**
     * Parse DuckDuckGo HTML results
     */
    parseDuckDuckGoResults(html, maxResults) {
        // This is a simplified parser - in practice you'd use a proper HTML parser
        const results = [];
        // Look for result links in the HTML
        const linkRegex = /<a[^>]+href="([^"]+)"[^>]*>([^<]+)<\/a>/g;
        let match;
        let rank = 1;
        while ((match = linkRegex.exec(html)) !== null && results.length < maxResults) {
            const url = match[1];
            const title = match[2];
            // Skip internal DuckDuckGo links
            if (url.startsWith('/') || url.includes('duckduckgo.com')) {
                continue;
            }
            try {
                const domain = new URL(url).hostname;
                results.push({
                    url,
                    title: title.trim(),
                    snippet: '', // DuckDuckGo doesn't provide snippets in HTML
                    domain,
                    rank: rank++
                });
            }
            catch (error) {
                // Skip invalid URLs
                continue;
            }
        }
        return results;
    }
    /**
     * Set API key for search provider
     */
    setApiKey(apiKey) {
        this.apiKey = apiKey;
    }
    /**
     * Change search provider
     */
    setProvider(provider) {
        this.provider = provider;
    }
}
