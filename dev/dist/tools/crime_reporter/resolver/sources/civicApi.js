/**
 * Civic API Adapter
 *
 * Optional integration with civic APIs for enhanced jurisdiction resolution
 * and official contact information.
 */
export class CivicApiAdapter {
    apiKey;
    baseUrl;
    constructor(apiKey, baseUrl = 'https://www.googleapis.com/civicinfo/v2') {
        this.apiKey = apiKey;
        this.baseUrl = baseUrl;
    }
    /**
     * Search for government offices by location
     */
    async searchOffices(location) {
        try {
            const address = await this.normalizeLocation(location);
            const url = `${this.baseUrl}/representatives?address=${encodeURIComponent(address)}&key=${this.apiKey}`;
            const response = await fetch(url);
            const data = await response.json();
            return this.parseCivicResults(data);
        }
        catch (error) {
            console.error('Civic API error:', error);
            return [];
        }
    }
    /**
     * Get specific office information
     */
    async getOfficeInfo(officeId) {
        try {
            const url = `${this.baseUrl}/representatives?address=${encodeURIComponent(officeId)}&key=${this.apiKey}`;
            const response = await fetch(url);
            const data = await response.json();
            const offices = this.parseCivicResults(data);
            return offices.length > 0 ? offices[0] : null;
        }
        catch (error) {
            console.error('Civic API office lookup error:', error);
            return null;
        }
    }
    /**
     * Normalize location to address string
     */
    async normalizeLocation(location) {
        if (typeof location === 'string') {
            return location;
        }
        // Reverse geocode lat/lon to address
        // This would typically use a geocoding service
        // For now, return a placeholder
        return `${location.lat},${location.lon}`;
    }
    /**
     * Parse Civic API results
     */
    parseCivicResults(data) {
        const results = [];
        if (!data.offices || !Array.isArray(data.offices)) {
            return results;
        }
        for (const office of data.offices) {
            const result = this.parseOffice(office, data);
            if (result) {
                results.push(result);
            }
        }
        return results;
    }
    /**
     * Parse individual office data
     */
    parseOffice(office, data) {
        const name = office.name;
        const type = this.determineOfficeType(name);
        // Skip non-law enforcement offices
        if (!this.isLawEnforcementOffice(type)) {
            return null;
        }
        // Get contact information from officials
        const officials = this.getOfficialsForOffice(office, data);
        const contact = this.extractContactInfo(officials);
        return {
            name,
            type,
            contact,
            jurisdiction: this.extractJurisdiction(data),
            services: this.extractServices(name, officials)
        };
    }
    /**
     * Determine office type from name
     */
    determineOfficeType(name) {
        const lowerName = name.toLowerCase();
        if (lowerName.includes('sheriff')) {
            return 'sheriff';
        }
        if (lowerName.includes('police')) {
            return 'police';
        }
        if (lowerName.includes('state') || lowerName.includes('bureau')) {
            return 'state';
        }
        if (lowerName.includes('federal') || lowerName.includes('fbi')) {
            return 'federal';
        }
        return 'police'; // Default
    }
    /**
     * Check if office is law enforcement related
     */
    isLawEnforcementOffice(type) {
        return ['police', 'sheriff', 'state', 'federal'].includes(type);
    }
    /**
     * Get officials associated with an office
     */
    getOfficialsForOffice(office, data) {
        if (!data.officials || !office.officialIndices) {
            return [];
        }
        return office.officialIndices.map((index) => data.officials[index]);
    }
    /**
     * Extract contact information from officials
     */
    extractContactInfo(officials) {
        const contact = {};
        for (const official of officials) {
            // Phone
            if (official.phones && official.phones.length > 0 && !contact.phone) {
                contact.phone = official.phones[0];
            }
            // Email
            if (official.emails && official.emails.length > 0 && !contact.email) {
                contact.email = official.emails[0];
            }
            // Website
            if (official.urls && official.urls.length > 0 && !contact.website) {
                contact.website = official.urls[0];
            }
            // Address
            if (official.address && official.address.length > 0 && !contact.address) {
                const addr = official.address[0];
                contact.address = [
                    addr.line1,
                    addr.line2,
                    addr.city,
                    addr.state,
                    addr.zip
                ].filter(Boolean).join(', ');
            }
        }
        return contact;
    }
    /**
     * Extract jurisdiction information
     */
    extractJurisdiction(data) {
        const normalizedInput = data.normalizedInput;
        return {
            city: normalizedInput?.city,
            county: normalizedInput?.county,
            state: normalizedInput?.state || 'Unknown',
            zip: normalizedInput?.zip
        };
    }
    /**
     * Extract available services
     */
    extractServices(name, officials) {
        const services = [];
        // Common law enforcement services
        const commonServices = [
            'crime reporting',
            'emergency response',
            'investigation',
            'patrol',
            'community outreach'
        ];
        // Add services based on office name
        const lowerName = name.toLowerCase();
        if (lowerName.includes('cyber') || lowerName.includes('internet')) {
            services.push('cybercrime reporting');
        }
        if (lowerName.includes('fraud')) {
            services.push('fraud investigation');
        }
        if (lowerName.includes('drug')) {
            services.push('drug enforcement');
        }
        // Add common services
        services.push(...commonServices);
        return [...new Set(services)]; // Remove duplicates
    }
    /**
     * Search for crime reporting services specifically
     */
    async searchCrimeReportingServices(location) {
        const allOffices = await this.searchOffices(location);
        // Filter for offices that likely handle crime reporting
        return allOffices.filter(office => office.services.some(service => service.toLowerCase().includes('crime') ||
            service.toLowerCase().includes('reporting')));
    }
    /**
     * Get emergency contact information
     */
    async getEmergencyContacts(location) {
        const offices = await this.searchOffices(location);
        const contacts = {};
        for (const office of offices) {
            if (office.contact.phone) {
                contacts[office.type] = office.contact.phone;
            }
        }
        return contacts;
    }
}
