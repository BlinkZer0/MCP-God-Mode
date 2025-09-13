/**
 * Heuristics Scorer
 *
 * Scores search results based on official domain indicators,
 * content quality, and trustworthiness signals.
 */
export class HeuristicsScorer {
    officialTlds = ['.gov', '.us', '.mil'];
    officialKeywords = [
        'police', 'sheriff', 'department', 'bureau', 'official',
        'government', 'municipal', 'county', 'state', 'federal'
    ];
    suspiciousKeywords = [
        'scam', 'fake', 'unofficial', 'third-party', 'advertisement'
    ];
    /**
     * Score a search result based on official indicators
     */
    async scoreResult(result) {
        let score = 0;
        const { url, title, snippet, domain, type } = result;
        const content = `${title} ${snippet}`.toLowerCase();
        // Base score for official TLDs
        score += this.scoreOfficialTld(domain);
        // Score based on official keywords
        score += this.scoreOfficialKeywords(content);
        // Penalize suspicious content
        score -= this.scoreSuspiciousContent(content);
        // Score based on HTTPS
        score += this.scoreHttps(url);
        // Score based on domain structure
        score += this.scoreDomainStructure(domain);
        // Score based on content quality
        score += this.scoreContentQuality(title, snippet);
        // Score based on jurisdiction type
        score += this.scoreJurisdictionType(type);
        // Normalize to 0-1 range
        return Math.max(0, Math.min(1, score));
    }
    /**
     * Score official top-level domains
     */
    scoreOfficialTld(domain) {
        for (const tld of this.officialTlds) {
            if (domain.endsWith(tld)) {
                return 0.4; // High score for official TLDs
            }
        }
        return 0;
    }
    /**
     * Score official keywords in content
     */
    scoreOfficialKeywords(content) {
        let score = 0;
        const keywordCount = this.officialKeywords.filter(keyword => content.includes(keyword)).length;
        // Score based on number of official keywords found
        score += Math.min(0.3, keywordCount * 0.05);
        // Bonus for specific high-value keywords
        if (content.includes('police department'))
            score += 0.1;
        if (content.includes('sheriff department'))
            score += 0.1;
        if (content.includes('official website'))
            score += 0.1;
        if (content.includes('government'))
            score += 0.05;
        return score;
    }
    /**
     * Penalize suspicious content
     */
    scoreSuspiciousContent(content) {
        let penalty = 0;
        for (const keyword of this.suspiciousKeywords) {
            if (content.includes(keyword)) {
                penalty += 0.2;
            }
        }
        // Penalize commercial indicators
        if (content.includes('advertisement') || content.includes('sponsored')) {
            penalty += 0.3;
        }
        return penalty;
    }
    /**
     * Score HTTPS usage
     */
    scoreHttps(url) {
        return url.startsWith('https://') ? 0.1 : -0.1;
    }
    /**
     * Score domain structure
     */
    scoreDomainStructure(domain) {
        let score = 0;
        // Prefer shorter, cleaner domains
        const parts = domain.split('.');
        if (parts.length <= 3) {
            score += 0.05;
        }
        // Prefer domains with official structure
        if (domain.includes('police') || domain.includes('sheriff')) {
            score += 0.1;
        }
        // Penalize subdomains that look unofficial
        if (domain.includes('blog.') || domain.includes('news.')) {
            score -= 0.1;
        }
        return score;
    }
    /**
     * Score content quality
     */
    scoreContentQuality(title, snippet) {
        let score = 0;
        // Prefer descriptive titles
        if (title.length > 20 && title.length < 100) {
            score += 0.05;
        }
        // Prefer informative snippets
        if (snippet.length > 50) {
            score += 0.05;
        }
        // Prefer content that mentions reporting functionality
        const reportingKeywords = ['report', 'file', 'submit', 'online', 'form'];
        const hasReportingKeywords = reportingKeywords.some(keyword => (title + ' ' + snippet).toLowerCase().includes(keyword));
        if (hasReportingKeywords) {
            score += 0.1;
        }
        return score;
    }
    /**
     * Score jurisdiction type
     */
    scoreJurisdictionType(type) {
        const typeScores = {
            'federal': 0.2,
            'state': 0.15,
            'sheriff': 0.1,
            'police': 0.1,
            'tipline': 0.05,
            'other': 0
        };
        return typeScores[type] || 0;
    }
    /**
     * Check if domain is likely official
     */
    isOfficialDomain(domain) {
        // Check for official TLDs
        if (this.officialTlds.some(tld => domain.endsWith(tld))) {
            return true;
        }
        // Check for known official patterns
        const officialPatterns = [
            /^[a-z]+\.gov$/,
            /^[a-z]+\.us$/,
            /^[a-z]+police\.org$/,
            /^[a-z]+sheriff\.org$/
        ];
        return officialPatterns.some(pattern => pattern.test(domain));
    }
    /**
     * Extract confidence level from score
     */
    getConfidenceLevel(score) {
        if (score >= 0.7)
            return 'high';
        if (score >= 0.4)
            return 'medium';
        return 'low';
    }
    /**
     * Get explanation for score
     */
    getScoreExplanation(result, score) {
        const explanations = [];
        const { url, title, snippet, domain } = result;
        const content = `${title} ${snippet}`.toLowerCase();
        // Official TLD
        if (this.officialTlds.some(tld => domain.endsWith(tld))) {
            explanations.push('Official government domain (.gov/.us/.mil)');
        }
        // HTTPS
        if (url.startsWith('https://')) {
            explanations.push('Secure HTTPS connection');
        }
        else {
            explanations.push('Warning: Not using HTTPS');
        }
        // Official keywords
        const officialCount = this.officialKeywords.filter(keyword => content.includes(keyword)).length;
        if (officialCount > 0) {
            explanations.push(`Contains ${officialCount} official keywords`);
        }
        // Reporting functionality
        if (content.includes('report') || content.includes('file')) {
            explanations.push('Mentions reporting functionality');
        }
        // Suspicious content
        const suspiciousCount = this.suspiciousKeywords.filter(keyword => content.includes(keyword)).length;
        if (suspiciousCount > 0) {
            explanations.push(`Warning: Contains ${suspiciousCount} suspicious keywords`);
        }
        return explanations;
    }
}
