/**
 * Jurisdiction Resolver
 *
 * Resolves geographic locations to appropriate law enforcement agencies
 * and reporting channels with official site detection and scoring.
 */
import { WebSearchAdapter } from './sources/webSearch.js';
import { HeuristicsScorer } from './sources/heuristics.js';
import { CivicApiAdapter } from './sources/civicApi.js';
export class JurisdictionResolver {
    webSearch;
    heuristics;
    civicApi;
    constructor(config) {
        this.webSearch = new WebSearchAdapter();
        this.heuristics = new HeuristicsScorer();
        if (config?.civicApiKey) {
            this.civicApi = new CivicApiAdapter(config.civicApiKey);
        }
    }
    /**
     * Search for appropriate jurisdictions and reporting channels
     */
    async searchJurisdiction(options) {
        const { location, crimeType, maxResults = 10, includeFederal = true } = options;
        // Normalize location to lat/lon if needed
        const geoLocation = await this.normalizeLocation(location);
        // Build search queries
        const queries = this.buildSearchQueries(geoLocation, crimeType);
        // Search for official sites
        const searchResults = await Promise.all(queries.map(query => this.webSearch.search(query)));
        // Extract and score jurisdictions
        const jurisdictions = await this.extractJurisdictions(searchResults, geoLocation);
        // Add federal options if requested
        if (includeFederal && this.isFederalCrime(crimeType)) {
            jurisdictions.push(...this.getFederalJurisdictions(crimeType));
        }
        // Sort by score and return top results
        return jurisdictions
            .sort((a, b) => b.score - a.score)
            .slice(0, maxResults);
    }
    /**
     * Normalize location string to lat/lon coordinates
     */
    async normalizeLocation(location) {
        if (typeof location === 'object' && location.lat && location.lon) {
            return { ...location, raw: `${location.lat},${location.lon}` };
        }
        // Use geocoding service (implement with your preferred provider)
        const geoResult = await this.geocodeLocation(location);
        return {
            lat: geoResult.lat,
            lon: geoResult.lon,
            raw: location
        };
    }
    /**
     * Geocode location string to coordinates
     */
    async geocodeLocation(location) {
        // Implementation depends on your geocoding provider
        // For now, return a placeholder
        throw new Error('Geocoding not implemented - provide lat/lon coordinates');
    }
    /**
     * Build search queries for finding official reporting sites
     */
    buildSearchQueries(geoLocation, crimeType) {
        const baseQueries = [
            `"report a crime online" ${geoLocation.raw}`,
            `"police department online reporting" ${geoLocation.raw}`,
            `"sheriff department" ${geoLocation.raw} "online report"`,
            `"file a police report" ${geoLocation.raw}`,
            `"crime reporting" ${geoLocation.raw} site:.gov`,
        ];
        if (crimeType) {
            const crimeSpecific = [
                `"report ${crimeType}" ${geoLocation.raw} site:.gov`,
                `"${crimeType} reporting" ${geoLocation.raw} police`,
                `"cybercrime reporting" ${geoLocation.raw}`,
                `"fraud reporting" ${geoLocation.raw}`,
            ];
            baseQueries.push(...crimeSpecific);
        }
        return baseQueries;
    }
    /**
     * Extract jurisdictions from search results and score them
     */
    async extractJurisdictions(searchResults, geoLocation) {
        const jurisdictions = new Map();
        for (const results of searchResults) {
            for (const result of results) {
                const jurisdiction = await this.parseSearchResult(result, geoLocation);
                if (jurisdiction) {
                    const key = jurisdiction.domain;
                    if (!jurisdictions.has(key) || jurisdictions.get(key).score < jurisdiction.score) {
                        jurisdictions.set(key, jurisdiction);
                    }
                }
            }
        }
        return Array.from(jurisdictions.values());
    }
    /**
     * Parse individual search result into jurisdiction
     */
    async parseSearchResult(result, geoLocation) {
        const url = result.url;
        const title = result.title;
        const snippet = result.snippet;
        // Extract domain and basic info
        const domain = new URL(url).hostname;
        const name = this.extractJurisdictionName(title, snippet, domain);
        const type = this.determineJurisdictionType(domain, title, snippet);
        // Score the result
        const score = await this.heuristics.scoreResult({
            url,
            title,
            snippet,
            domain,
            type
        });
        // Only include high-confidence official results
        if (score < 0.3) {
            return null;
        }
        // Extract reporting channels
        const channels = await this.extractChannels(url, title, snippet);
        return {
            name,
            type,
            channels,
            score,
            domain,
            description: snippet
        };
    }
    /**
     * Extract jurisdiction name from search result
     */
    extractJurisdictionName(title, snippet, domain) {
        // Try to extract from title first
        const titleMatch = title.match(/([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+(?:Police|Sheriff|Department|Bureau)/i);
        if (titleMatch) {
            return titleMatch[1];
        }
        // Fall back to domain-based extraction
        const domainParts = domain.split('.');
        if (domainParts.length >= 2) {
            const cityPart = domainParts[0];
            return cityPart.charAt(0).toUpperCase() + cityPart.slice(1);
        }
        return domain;
    }
    /**
     * Determine jurisdiction type from domain and content
     */
    determineJurisdictionType(domain, title, snippet) {
        const content = `${title} ${snippet}`.toLowerCase();
        if (domain.includes('fbi.gov') || domain.includes('ic3.gov') || content.includes('fbi')) {
            return 'federal';
        }
        if (domain.includes('sheriff') || content.includes('sheriff')) {
            return 'sheriff';
        }
        if (domain.includes('state') || content.includes('state bureau')) {
            return 'state';
        }
        if (content.includes('crime stoppers') || content.includes('tipline')) {
            return 'tipline';
        }
        return 'police';
    }
    /**
     * Extract available reporting channels from a jurisdiction page
     */
    async extractChannels(url, title, snippet) {
        const channels = [];
        // Check for online form indicators
        if (snippet.toLowerCase().includes('online form') ||
            snippet.toLowerCase().includes('submit report') ||
            snippet.toLowerCase().includes('file report')) {
            channels.push({
                mode: 'form',
                urlOrAddress: url,
                notes: 'Online reporting form',
                priority: 1
            });
        }
        // Check for email indicators
        if (snippet.includes('@') || snippet.toLowerCase().includes('email')) {
            const emailMatch = snippet.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
            if (emailMatch) {
                channels.push({
                    mode: 'email',
                    urlOrAddress: emailMatch[1],
                    notes: 'Email reporting',
                    priority: 2
                });
            }
        }
        // Add phone as fallback
        channels.push({
            mode: 'phone',
            urlOrAddress: 'See website for contact information',
            notes: 'Phone reporting (fallback)',
            priority: 3
        });
        return channels;
    }
    /**
     * Check if crime type requires federal jurisdiction
     */
    isFederalCrime(crimeType) {
        if (!crimeType)
            return false;
        const federalCrimes = [
            'cyber', 'cybercrime', 'fraud', 'identity theft', 'hacking',
            'terrorism', 'drug trafficking', 'money laundering'
        ];
        return federalCrimes.some(federal => crimeType.toLowerCase().includes(federal));
    }
    /**
     * Get federal jurisdiction options for specific crime types
     */
    getFederalJurisdictions(crimeType) {
        const federal = [];
        // FBI IC3 for cybercrime
        if (crimeType && crimeType.toLowerCase().includes('cyber')) {
            federal.push({
                name: 'FBI Internet Crime Complaint Center (IC3)',
                type: 'federal',
                channels: [{
                        mode: 'form',
                        urlOrAddress: 'https://www.ic3.gov/Home/FileComplaint',
                        notes: 'Official FBI cybercrime reporting portal',
                        priority: 1
                    }],
                score: 0.95,
                domain: 'ic3.gov',
                description: 'Federal cybercrime reporting portal'
            });
        }
        // General FBI tip line
        federal.push({
            name: 'FBI Tips',
            type: 'federal',
            channels: [{
                    mode: 'form',
                    urlOrAddress: 'https://tips.fbi.gov/',
                    notes: 'FBI tip submission portal',
                    priority: 2
                }],
            score: 0.9,
            domain: 'fbi.gov',
            description: 'Federal tip submission portal'
        });
        return federal;
    }
}
