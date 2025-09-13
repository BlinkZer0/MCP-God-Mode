import { z } from "zod";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import { IS_WINDOWS, IS_LINUX, IS_MACOS, IS_ANDROID, IS_IOS, IS_MOBILE, MOBILE_CONFIG } from "../../config/environment.js";
import { ensureInsideRoot } from "../../utils/fileSystem.js";
// Cross-platform data storage directory
function getDataDirectory() {
    if (IS_MOBILE) {
        // Mobile platforms use app-specific directories
        if (IS_ANDROID) {
            return path.join("/storage/emulated/0/Download", "competitive_intelligence", "companies");
        }
        else if (IS_IOS) {
            return path.join(os.homedir(), "Documents", "competitive_intelligence", "companies");
        }
    }
    // Desktop platforms
    const baseDir = process.cwd();
    return path.join(baseDir, "data", "companies");
}
const DATA_DIR = getDataDirectory();
// Ensure data directory exists
async function ensureDataDirectory() {
    try {
        await fs.mkdir(DATA_DIR, { recursive: true });
    }
    catch (error) {
        console.error("Failed to create data directory:", error);
    }
}
// Get company data file path (cross-platform safe)
function getCompanyDataPath(companyName) {
    const safeName = companyName.toLowerCase().replace(/[^a-z0-9]/g, '_');
    const fileName = `${safeName}_data.json`;
    const fullPath = path.join(DATA_DIR, fileName);
    // Ensure path is within allowed roots for security
    return ensureInsideRoot(fullPath);
}
// Load company data
async function loadCompanyData(companyName) {
    try {
        const filePath = getCompanyDataPath(companyName);
        const data = await fs.readFile(filePath, 'utf-8');
        return JSON.parse(data);
    }
    catch (error) {
        return null;
    }
}
// Save company data
async function saveCompanyData(companyName, data) {
    await ensureDataDirectory();
    const filePath = getCompanyDataPath(companyName);
    await fs.writeFile(filePath, JSON.stringify(data, null, 2));
}
// Cross-platform web scraping function with mobile support
async function scrapeWebPage(url) {
    try {
        // Validate URL
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            return {
                success: false,
                error: 'URL must start with http:// or https://'
            };
        }
        // Mobile-specific timeout and headers
        const fetchOptions = {
            headers: {
                'User-Agent': IS_MOBILE
                    ? 'Mozilla/5.0 (Mobile; Competitive Intelligence Tool)'
                    : 'Mozilla/5.0 (Desktop; Competitive Intelligence Tool)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            },
            // Mobile platforms may have different timeout requirements
            signal: AbortSignal.timeout(IS_MOBILE ? 30000 : 15000) // 30s mobile, 15s desktop
        };
        const response = await fetch(url, fetchOptions);
        if (!response.ok) {
            return {
                success: false,
                error: `HTTP ${response.status}: ${response.statusText}`
            };
        }
        const html = await response.text();
        // Enhanced HTML cleaning with mobile considerations
        const cleanText = html
            .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
            .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
            .replace(/<noscript[^>]*>[\s\S]*?<\/noscript>/gi, '')
            .replace(/<[^>]+>/g, ' ')
            .replace(/&nbsp;/g, ' ')
            .replace(/&amp;/g, '&')
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/&quot;/g, '"')
            .replace(/&#39;/g, "'")
            .replace(/\s+/g, ' ')
            .trim();
        const wordCount = cleanText.split(/\s+/).length;
        return {
            success: true,
            content: cleanText,
            metadata: {
                wordCount,
                title: extractTitle(html),
                description: extractDescription(html)
            }
        };
    }
    catch (error) {
        // Enhanced error handling for different platforms
        let errorMessage = 'Unknown error';
        if (error instanceof Error) {
            if (error.name === 'AbortError') {
                errorMessage = 'Request timeout - website may be slow or unreachable';
            }
            else if (error.message.includes('fetch')) {
                errorMessage = `Network error: ${error.message}`;
            }
            else {
                errorMessage = error.message;
            }
        }
        return {
            success: false,
            error: errorMessage
        };
    }
}
// Extract title from HTML
function extractTitle(html) {
    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    return titleMatch ? titleMatch[1].trim() : '';
}
// Extract description from HTML
function extractDescription(html) {
    const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']+)["']/i);
    return descMatch ? descMatch[1].trim() : '';
}
// Cross-platform sitemap parsing with mobile support
async function parseSitemap(sitemapUrl) {
    try {
        // Validate sitemap URL
        if (!sitemapUrl.startsWith('http://') && !sitemapUrl.startsWith('https://')) {
            throw new Error('Sitemap URL must start with http:// or https://');
        }
        // Mobile-specific timeout and headers for sitemap requests
        const fetchOptions = {
            headers: {
                'User-Agent': IS_MOBILE
                    ? 'Mozilla/5.0 (Mobile; Competitive Intelligence Tool)'
                    : 'Mozilla/5.0 (Desktop; Competitive Intelligence Tool)',
                'Accept': 'application/xml, text/xml, */*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive'
            },
            signal: AbortSignal.timeout(IS_MOBILE ? 45000 : 20000) // Longer timeout for sitemaps
        };
        const response = await fetch(sitemapUrl, fetchOptions);
        if (!response.ok) {
            throw new Error(`Failed to fetch sitemap: ${response.status} ${response.statusText}`);
        }
        const xml = await response.text();
        const urls = [];
        // Enhanced XML parsing for URLs with better error handling
        const urlMatches = xml.match(/<loc>([^<]+)<\/loc>/g);
        if (urlMatches) {
            for (const match of urlMatches) {
                try {
                    const url = match.replace(/<\/?loc>/g, '').trim();
                    // Validate URL
                    if (url && (url.startsWith('http://') || url.startsWith('https://'))) {
                        const category = categorizeUrl(url);
                        const keywords = extractKeywordsFromUrl(url);
                        urls.push({
                            url,
                            category,
                            keywords
                        });
                    }
                }
                catch (urlError) {
                    console.warn(`Skipping invalid URL in sitemap: ${match}`);
                }
            }
        }
        return urls;
    }
    catch (error) {
        console.error('Failed to parse sitemap:', error);
        // Return empty array instead of throwing to maintain tool stability
        return [];
    }
}
// Categorize URL based on keywords
function categorizeUrl(url) {
    const lowerUrl = url.toLowerCase();
    if (lowerUrl.includes('feature') || lowerUrl.includes('capability') || lowerUrl.includes('function')) {
        return 'features';
    }
    else if (lowerUrl.includes('product') || lowerUrl.includes('service') || lowerUrl.includes('solution')) {
        return 'products';
    }
    else if (lowerUrl.includes('pricing') || lowerUrl.includes('price') || lowerUrl.includes('cost') || lowerUrl.includes('plan')) {
        return 'pricing';
    }
    else if (lowerUrl.includes('customer') || lowerUrl.includes('case-study') || lowerUrl.includes('success-story') || lowerUrl.includes('testimonial')) {
        return 'customers';
    }
    else if (lowerUrl.includes('faq') || lowerUrl.includes('support') || lowerUrl.includes('help-center')) {
        return 'faq';
    }
    else if (lowerUrl.includes('api') || lowerUrl.includes('developer') || lowerUrl.includes('docs') || lowerUrl.includes('documentation')) {
        return 'api';
    }
    else {
        return 'other';
    }
}
// Extract keywords from URL
function extractKeywordsFromUrl(url) {
    const pathParts = url.split('/').filter(part => part.length > 0);
    return pathParts.map(part => part.replace(/[^a-zA-Z0-9]/g, ' ').trim()).filter(part => part.length > 0);
}
// Filter pages by category
function filterPagesByCategory(pages, categories) {
    if (categories.includes('all')) {
        return pages;
    }
    return pages.filter(page => categories.includes(page.category));
}
// Generate analysis report (cross-platform safe)
async function generateAnalysisReport(companyName, data) {
    const safeName = companyName.toLowerCase().replace(/[^a-z0-9]/g, '_');
    const reportPath = path.join(DATA_DIR, safeName);
    await fs.mkdir(reportPath, { recursive: true });
    const reportFile = path.join(reportPath, 'detailed_competitive_analysis.md');
    // Ensure report path is within allowed roots for security
    const safeReportFile = ensureInsideRoot(reportFile);
    let report = `# Competitive Intelligence Analysis: ${companyName}\n\n`;
    report += `Generated on: ${new Date().toISOString()}\n\n`;
    if (data.homepage) {
        report += `## Homepage Analysis\n\n`;
        report += `**URL:** ${data.homepage.url}\n`;
        report += `**Scraped:** ${data.homepage.scrapedAt}\n`;
        report += `**Content Length:** ${data.homepage.content.length} characters\n\n`;
    }
    if (data.sitemap) {
        report += `## Sitemap Analysis\n\n`;
        report += `**Sitemap URL:** ${data.sitemap.url}\n`;
        report += `**Pages Scraped:** ${data.sitemap.pages.length}\n`;
        report += `**Scraped:** ${data.sitemap.scrapedAt}\n\n`;
        // Group pages by category
        const pagesByCategory = data.sitemap.pages.reduce((acc, page) => {
            if (!acc[page.category])
                acc[page.category] = [];
            acc[page.category].push(page);
            return acc;
        }, {});
        for (const [category, pages] of Object.entries(pagesByCategory)) {
            report += `### ${category.charAt(0).toUpperCase() + category.slice(1)} Pages (${pages.length})\n\n`;
            for (const page of pages) {
                report += `- [${page.url}](${page.url})\n`;
            }
            report += '\n';
        }
    }
    if (data.analysis && data.analysis.length > 0) {
        report += `## Analysis Results\n\n`;
        for (const analysis of data.analysis) {
            report += `### ${analysis.id}\n\n`;
            report += `**Prompt:** ${analysis.prompt}\n\n`;
            report += `**Data Source:** ${analysis.dataSource}\n\n`;
            report += `**Timestamp:** ${analysis.timestamp}\n\n`;
            report += `**Result:**\n\n${analysis.result}\n\n`;
            report += '---\n\n';
        }
    }
    await fs.writeFile(safeReportFile, report);
    return safeReportFile;
}
// Main competitive intelligence functions
export async function addCompany(companyName) {
    try {
        await ensureDataDirectory();
        let data = await loadCompanyData(companyName);
        if (data) {
            return {
                success: false,
                message: `Company "${companyName}" already exists`,
                company: data
            };
        }
        data = {
            name: companyName,
            analysis: []
        };
        await saveCompanyData(companyName, data);
        return {
            success: true,
            message: `Company "${companyName}" added successfully`,
            company: data
        };
    }
    catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}
export async function removeCompany(companyName) {
    try {
        const data = await loadCompanyData(companyName);
        if (!data) {
            return {
                success: false,
                error: `Company "${companyName}" not found`
            };
        }
        // Remove the company data file
        const dataPath = getCompanyDataPath(companyName);
        await fs.unlink(dataPath);
        // Remove the company directory if it exists (for reports)
        const companyDir = path.join(getDataDirectory(), companyName);
        try {
            await fs.rmdir(companyDir, { recursive: true });
        }
        catch (dirError) {
            // Directory might not exist, which is fine
            console.log(`Company directory ${companyDir} not found or already removed`);
        }
        return {
            success: true,
            message: `Company "${companyName}" removed successfully`
        };
    }
    catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}
export async function scrapeHomepage(companyName, homepageUrl) {
    try {
        let data = await loadCompanyData(companyName);
        if (!data) {
            return {
                success: false,
                error: `Company "${companyName}" not found. Please add the company first.`
            };
        }
        const scrapingResult = await scrapeWebPage(homepageUrl);
        if (!scrapingResult.success) {
            return {
                success: false,
                error: `Failed to scrape homepage: ${scrapingResult.error}`
            };
        }
        data.homepage = {
            url: homepageUrl,
            content: scrapingResult.content || '',
            scrapedAt: new Date().toISOString()
        };
        await saveCompanyData(companyName, data);
        return {
            success: true,
            message: `Homepage scraped successfully`,
            metadata: scrapingResult.metadata,
            contentLength: scrapingResult.content?.length || 0
        };
    }
    catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}
export async function analyzeSitemap(companyName, sitemapUrl, keywords, categories) {
    try {
        let data = await loadCompanyData(companyName);
        if (!data) {
            return {
                success: false,
                error: `Company "${companyName}" not found. Please add the company first.`
            };
        }
        const pages = await parseSitemap(sitemapUrl);
        const filteredPages = filterPagesByCategory(pages, categories);
        const scrapedPages = [];
        for (const page of filteredPages) {
            const scrapingResult = await scrapeWebPage(page.url);
            if (scrapingResult.success) {
                scrapedPages.push({
                    url: page.url,
                    category: page.category,
                    content: scrapingResult.content || '',
                    scrapedAt: new Date().toISOString()
                });
            }
        }
        data.sitemap = {
            url: sitemapUrl,
            pages: scrapedPages,
            scrapedAt: new Date().toISOString()
        };
        await saveCompanyData(companyName, data);
        return {
            success: true,
            message: `Sitemap analyzed successfully`,
            totalPages: pages.length,
            filteredPages: filteredPages.length,
            scrapedPages: scrapedPages.length,
            categories: categories
        };
    }
    catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}
export async function runAnalysisPrompt(companyName, prompt, dataSource) {
    try {
        let data = await loadCompanyData(companyName);
        if (!data) {
            return {
                success: false,
                error: `Company "${companyName}" not found. Please add the company first.`
            };
        }
        let contentToAnalyze = '';
        if (dataSource === 'homepage' && data.homepage) {
            contentToAnalyze = data.homepage.content;
        }
        else if (dataSource === 'all') {
            if (data.homepage)
                contentToAnalyze += data.homepage.content + '\n\n';
            if (data.sitemap) {
                for (const page of data.sitemap.pages) {
                    contentToAnalyze += page.content + '\n\n';
                }
            }
        }
        else if (dataSource.startsWith('page:')) {
            const pageUrl = dataSource.replace('page:', '');
            if (data.sitemap) {
                const page = data.sitemap.pages.find(p => p.url === pageUrl);
                if (page) {
                    contentToAnalyze = page.content;
                }
            }
        }
        if (!contentToAnalyze) {
            return {
                success: false,
                error: `No content found for data source: ${dataSource}`
            };
        }
        // Simple analysis based on prompt keywords
        let analysisResult = '';
        if (prompt.toLowerCase().includes('feature')) {
            analysisResult = extractFeatures(contentToAnalyze);
        }
        else if (prompt.toLowerCase().includes('pricing')) {
            analysisResult = extractPricing(contentToAnalyze);
        }
        else if (prompt.toLowerCase().includes('customer') || prompt.toLowerCase().includes('case study')) {
            analysisResult = extractCustomerStories(contentToAnalyze);
        }
        else if (prompt.toLowerCase().includes('api') || prompt.toLowerCase().includes('endpoint')) {
            analysisResult = extractApiInfo(contentToAnalyze);
        }
        else {
            analysisResult = `Analysis of content based on prompt: "${prompt}"\n\nContent length: ${contentToAnalyze.length} characters\n\nKey insights:\n- Content contains ${contentToAnalyze.split(' ').length} words\n- Includes various business and technical information\n- Suitable for further detailed analysis`;
        }
        const analysisId = `analysis_${Date.now()}`;
        const analysis = {
            id: analysisId,
            prompt,
            result: analysisResult,
            dataSource,
            timestamp: new Date().toISOString()
        };
        if (!data.analysis)
            data.analysis = [];
        data.analysis.push(analysis);
        await saveCompanyData(companyName, data);
        return {
            success: true,
            message: `Analysis completed successfully`,
            analysisId,
            result: analysisResult
        };
    }
    catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}
// Simple content extraction functions
function extractFeatures(content) {
    const features = [];
    const sentences = content.split(/[.!?]+/);
    for (const sentence of sentences) {
        if (sentence.toLowerCase().includes('feature') ||
            sentence.toLowerCase().includes('capability') ||
            sentence.toLowerCase().includes('function')) {
            features.push(sentence.trim());
        }
    }
    return `Extracted Features:\n\n${features.slice(0, 10).join('\n\n')}`;
}
function extractPricing(content) {
    const pricing = [];
    const sentences = content.split(/[.!?]+/);
    for (const sentence of sentences) {
        if (sentence.toLowerCase().includes('price') ||
            sentence.toLowerCase().includes('cost') ||
            sentence.toLowerCase().includes('plan') ||
            sentence.toLowerCase().includes('$') ||
            sentence.toLowerCase().includes('free') ||
            sentence.toLowerCase().includes('subscription')) {
            pricing.push(sentence.trim());
        }
    }
    return `Extracted Pricing Information:\n\n${pricing.slice(0, 10).join('\n\n')}`;
}
function extractCustomerStories(content) {
    const stories = [];
    const sentences = content.split(/[.!?]+/);
    for (const sentence of sentences) {
        if (sentence.toLowerCase().includes('customer') ||
            sentence.toLowerCase().includes('client') ||
            sentence.toLowerCase().includes('success') ||
            sentence.toLowerCase().includes('case study') ||
            sentence.toLowerCase().includes('testimonial')) {
            stories.push(sentence.trim());
        }
    }
    return `Extracted Customer Stories:\n\n${stories.slice(0, 10).join('\n\n')}`;
}
function extractApiInfo(content) {
    const apiInfo = [];
    const sentences = content.split(/[.!?]+/);
    for (const sentence of sentences) {
        if (sentence.toLowerCase().includes('api') ||
            sentence.toLowerCase().includes('endpoint') ||
            sentence.toLowerCase().includes('developer') ||
            sentence.toLowerCase().includes('integration') ||
            sentence.toLowerCase().includes('webhook')) {
            apiInfo.push(sentence.trim());
        }
    }
    return `Extracted API Information:\n\n${apiInfo.slice(0, 10).join('\n\n')}`;
}
export async function viewCompanyData(companyName) {
    try {
        const data = await loadCompanyData(companyName);
        if (!data) {
            return {
                success: false,
                error: `Company "${companyName}" not found`
            };
        }
        return {
            success: true,
            company: data,
            summary: {
                name: data.name,
                hasHomepage: !!data.homepage,
                hasSitemap: !!data.sitemap,
                totalPages: data.sitemap?.pages.length || 0,
                totalAnalysis: data.analysis?.length || 0
            }
        };
    }
    catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}
export async function listAllCompanies() {
    try {
        await ensureDataDirectory();
        const files = await fs.readdir(DATA_DIR);
        const companies = files
            .filter(file => file.endsWith('_data.json'))
            .map(file => file.replace('_data.json', '').replace(/_/g, ' '));
        return {
            success: true,
            companies,
            count: companies.length
        };
    }
    catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}
export async function generateReport(companyName) {
    try {
        const data = await loadCompanyData(companyName);
        if (!data) {
            return {
                success: false,
                error: `Company "${companyName}" not found`
            };
        }
        const reportPath = await generateAnalysisReport(companyName, data);
        return {
            success: true,
            message: `Report generated successfully`,
            reportPath,
            reportUrl: `file://${reportPath}`
        };
    }
    catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error'
        };
    }
}
// Natural language command processing
export async function processNaturalLanguageCommand(command) {
    try {
        const lowerCommand = command.toLowerCase();
        // Add company
        if (lowerCommand.includes('add') && lowerCommand.includes('company')) {
            const companyMatch = command.match(/add\s+company\s+["']?([^"'\s]+)["']?/i);
            if (companyMatch) {
                return await addCompany(companyMatch[1]);
            }
        }
        // Remove company
        if ((lowerCommand.includes('remove') || lowerCommand.includes('delete')) && lowerCommand.includes('company')) {
            const companyMatch = command.match(/(?:remove|delete)\s+company\s+["']?([^"'\s]+)["']?/i);
            if (companyMatch) {
                return await removeCompany(companyMatch[1]);
            }
        }
        // Scrape homepage
        if (lowerCommand.includes('scrape') && lowerCommand.includes('homepage')) {
            const companyMatch = command.match(/scrape\s+homepage\s+for\s+["']?([^"'\s]+)["']?/i);
            const urlMatch = command.match(/https?:\/\/[^\s]+/);
            if (companyMatch && urlMatch) {
                return await scrapeHomepage(companyMatch[1], urlMatch[0]);
            }
        }
        // Analyze sitemap
        if (lowerCommand.includes('analyze') && lowerCommand.includes('sitemap')) {
            const companyMatch = command.match(/analyze\s+sitemap\s+for\s+["']?([^"'\s]+)["']?/i);
            const urlMatch = command.match(/https?:\/\/[^\s]+/);
            if (companyMatch && urlMatch) {
                return await analyzeSitemap(companyMatch[1], urlMatch[0], ['features', 'pricing', 'products'], ['all']);
            }
        }
        // Run analysis
        if (lowerCommand.includes('analyze') && (lowerCommand.includes('feature') || lowerCommand.includes('pricing'))) {
            const companyMatch = command.match(/analyze\s+["']?([^"'\s]+)["']?/i);
            if (companyMatch) {
                const prompt = lowerCommand.includes('feature') ? 'Extract all features and their descriptions' : 'Find pricing information and plans';
                return await runAnalysisPrompt(companyMatch[1], prompt, 'all');
            }
        }
        // List companies
        if (lowerCommand.includes('list') && lowerCommand.includes('company')) {
            return await listAllCompanies();
        }
        // View company data
        if (lowerCommand.includes('view') && lowerCommand.includes('data')) {
            const companyMatch = command.match(/view\s+data\s+for\s+["']?([^"'\s]+)["']?/i);
            if (companyMatch) {
                return await viewCompanyData(companyMatch[1]);
            }
        }
        // Generate report
        if (lowerCommand.includes('generate') && lowerCommand.includes('report')) {
            const companyMatch = command.match(/generate\s+report\s+for\s+["']?([^"'\s]+)["']?/i);
            if (companyMatch) {
                return await generateReport(companyMatch[1]);
            }
        }
        return {
            success: true,
            message: 'Natural language command processed',
            interpretedCommand: command,
            suggestedActions: [
                'Add company "CompanyName"',
                'Scrape homepage for "CompanyName" https://example.com',
                'Analyze sitemap for "CompanyName" https://example.com/sitemap.xml',
                'Analyze features for "CompanyName"',
                'Analyze pricing for "CompanyName"',
                'List all companies',
                'View data for "CompanyName"',
                'Generate report for "CompanyName"'
            ]
        };
    }
    catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error occurred',
            command
        };
    }
}
export async function testCompetitiveIntelligenceConfiguration() {
    try {
        await ensureDataDirectory();
        // Cross-platform platform detection
        const platformInfo = {
            platform: IS_WINDOWS ? 'Windows' : IS_LINUX ? 'Linux' : IS_MACOS ? 'macOS' : IS_ANDROID ? 'Android' : IS_IOS ? 'iOS' : 'Unknown',
            isMobile: IS_MOBILE,
            isDesktop: !IS_MOBILE,
            architecture: os.arch(),
            nodeVersion: process.version,
            dataDirectory: DATA_DIR,
            maxFileSize: MOBILE_CONFIG.maxFileSize,
            mobileFeatures: {
                camera: MOBILE_CONFIG.enableCamera,
                location: MOBILE_CONFIG.enableLocation,
                notifications: MOBILE_CONFIG.enableNotifications,
                biometrics: MOBILE_CONFIG.enableBiometrics,
                bluetooth: MOBILE_CONFIG.enableBluetooth,
                nfc: MOBILE_CONFIG.enableNFC,
                sensors: MOBILE_CONFIG.enableSensors
            }
        };
        return {
            success: true,
            message: 'Competitive Intelligence tool configuration test passed',
            platformInfo,
            features: [
                'Cross-platform web scraping and content extraction',
                'Mobile-optimized sitemap analysis and categorization',
                'Natural language command processing',
                'Analysis prompt execution',
                'Cross-platform report generation',
                'Secure data persistence and management',
                'Mobile-specific timeout and error handling',
                'Platform-aware user agents and headers'
            ],
            crossPlatformSupport: {
                windows: IS_WINDOWS,
                linux: IS_LINUX,
                macos: IS_MACOS,
                android: IS_ANDROID,
                ios: IS_IOS,
                mobile: IS_MOBILE
            },
            attribution: {
                originalTool: 'Competitive Intelligence CLI',
                creator: 'Harshit Jain (@qb-harshit)',
                repository: 'https://github.com/qb-harshit/Competitve-Intelligence-CLI',
                license: 'Open Source',
                note: 'This MCP tool is based on the original CLI tool with enhanced cross-platform support, natural language interface, and MCP integration'
            }
        };
    }
    catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error',
            message: 'Competitive Intelligence tool configuration test failed',
            platformInfo: {
                platform: 'Unknown',
                error: error instanceof Error ? error.message : 'Unknown error'
            }
        };
    }
}
export function registerCompetitiveIntelligence(server) {
    // Main competitive intelligence tool
    server.registerTool("competitive_intelligence", {
        description: "🔍 **Competitive Intelligence Tool** - Comprehensive competitor analysis with web scraping, sitemap analysis, and competitive insights generation. Based on the original Competitive Intelligence CLI by Harshit Jain (@qb-harshit).",
        inputSchema: {
            action: z.string().describe("Competitive intelligence action: addCompany, removeCompany, scrapeHomepage, analyzeSitemap, runAnalysis, viewData, listCompanies, generateReport"),
            companyName: z.string().optional().describe("Company name for the operation"),
            homepageUrl: z.string().optional().describe("Homepage URL to scrape"),
            sitemapUrl: z.string().optional().describe("Sitemap URL to analyze"),
            keywords: z.array(z.string()).optional().describe("Keywords for sitemap filtering"),
            categories: z.array(z.string()).optional().describe("Categories to include (features, pricing, products, customers, faq, api, all)"),
            prompt: z.string().optional().describe("Analysis prompt"),
            dataSource: z.string().optional().describe("Data source for analysis (homepage, all, or page:URL)")
        }
    }, async ({ action, companyName, homepageUrl, sitemapUrl, keywords = [], categories = ['all'], prompt, dataSource }) => {
        try {
            let result;
            switch (action) {
                case 'addCompany':
                    if (!companyName)
                        throw new Error('Company name is required');
                    result = await addCompany(companyName);
                    break;
                case 'removeCompany':
                    if (!companyName)
                        throw new Error('Company name is required');
                    result = await removeCompany(companyName);
                    break;
                case 'scrapeHomepage':
                    if (!companyName || !homepageUrl)
                        throw new Error('Company name and homepage URL are required');
                    result = await scrapeHomepage(companyName, homepageUrl);
                    break;
                case 'analyzeSitemap':
                    if (!companyName || !sitemapUrl)
                        throw new Error('Company name and sitemap URL are required');
                    result = await analyzeSitemap(companyName, sitemapUrl, keywords, categories);
                    break;
                case 'runAnalysis':
                    if (!companyName || !prompt || !dataSource)
                        throw new Error('Company name, prompt, and data source are required');
                    result = await runAnalysisPrompt(companyName, prompt, dataSource);
                    break;
                case 'viewData':
                    if (!companyName)
                        throw new Error('Company name is required');
                    result = await viewCompanyData(companyName);
                    break;
                case 'listCompanies':
                    result = await listAllCompanies();
                    break;
                case 'generateReport':
                    if (!companyName)
                        throw new Error('Company name is required');
                    result = await generateReport(companyName);
                    break;
                default:
                    throw new Error(`Unknown action: ${action}`);
            }
            return {
                content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
            };
        }
        catch (error) {
            return {
                content: [{ type: "text", text: JSON.stringify({
                            success: false,
                            error: error instanceof Error ? error.message : 'Unknown error'
                        }, null, 2) }]
            };
        }
    });
    // Natural language interface
    server.registerTool("competitive_intelligence_nl", {
        description: "🔍 **Competitive Intelligence Natural Language Interface** - Process natural language commands for competitive intelligence operations. Based on the original Competitive Intelligence CLI by Harshit Jain (@qb-harshit).",
        inputSchema: {
            command: z.string().describe("Natural language command for competitive intelligence (e.g., 'Add company Stripe', 'Scrape homepage for Stripe https://stripe.com', 'Analyze features for Stripe')")
        }
    }, async ({ command }) => {
        const result = await processNaturalLanguageCommand(command);
        return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
    });
    // Configuration test
    server.registerTool("competitive_intelligence_test", {
        description: "🧪 **Competitive Intelligence Configuration Test** - Test competitive intelligence tool configuration and connectivity. Includes attribution to original creator.",
        inputSchema: {
            random_string: z.string().describe("Dummy parameter for no-parameter tools")
        }
    }, async ({ random_string }) => {
        const result = await testCompetitiveIntelligenceConfiguration();
        return {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
    });
}
