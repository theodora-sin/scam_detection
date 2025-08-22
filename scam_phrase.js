// REFINED VERSION of scam_phrase_1755839789512.js
// Fixed: Better organization, consistent naming, modular export

// === SCAM DETECTION PATTERNS === //
const SCAM_PATTERNS = {
    // Urgency and pressure tactics
    URGENCY: [
        "urgent action required", "act now or lose forever", "limited time offer", "expires today",
        "immediate response required", "time sensitive", "last chance", "don't delay"
    ],
    
    // Prize and lottery scams
    PRIZES: [
        "claim your prize", "congratulations! you have won", "you've been selected", 
        "lottery winner", "cash prize", "free gift", "free money"
    ],
    
    // Account security threats
    SECURITY_THREATS: [
        "confirm your personal information", "verify your account", "update your details",
        "confirm your identity", "security verification required", "account suspended",
        "account locked", "unauthorized access detected"
    ],
    
    // Payment and financial scams
    FINANCIAL: [
        "wire transfer", "send money", "pay processing fee", "tax refund", "inheritance money",
        "investment opportunity", "guaranteed returns", "double your money"
    ],
    
    // Authority impersonation
    AUTHORITY: [
        "hsbc", "hm office", "google verification", "paypal security", "amazon security", 
        "microsoft support", "apple support", "irs notice", "government official"
    ],
    
    // Malicious actions
    MALICIOUS_ACTIONS: [
        "click to unlock", "download now", "install software", "run this file", 
        "enable macros", "update your browser", "install codec"
    ],
    
    // Social engineering
    SOCIAL_ENGINEERING: [
        "don't tell anyone", "confidential matter", "help me transfer money", 
        "i am dying", "refugee", "widow", "stranded", "emergency situation"
    ]
};

// === DOMAIN CLASSIFICATIONS === //
const DOMAIN_LISTS = {
    // Known suspicious/temporary domains
    SUSPICIOUS: [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link",
        "secure-bank", "paypal-secure", "amazon-security", "microsoft-support", 
        "apple-security", "google-verify", "facebook-security"
    ],
    
    // Suspicious TLDs
    SUSPICIOUS_TLDS: ["tk", "ml", "ga", "cf", "xyz", "click", "download"],
    
    // Legitimate domains (whitelist)
    LEGITIMATE: [
        "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
        "facebook.com", "twitter.com", "linkedin.com", "github.com", "stackoverflow.com",
        "wikipedia.org", "reddit.com", "youtube.com", "gmail.com", "outlook.com",
        "gov", "edu", "org"
    ]
};

// === SCAM TYPES DATABASE === //
const SCAM_TYPES = [
    {
        id: "phishing-email",
        name: "Phishing Email",
        category: "Identity Theft",
        description: "Fraudulent emails designed to steal personal information by impersonating legitimate organizations.",
        warning_signs: "Urgent language, suspicious sender addresses, requests for personal information, poor grammar/spelling, generic greetings",
        example: "Email claiming your account will be closed unless you click a link and verify your credentials.",
        prevention_tips: "Always verify sender authenticity, check URLs carefully, never provide sensitive information via email, use official websites directly",
        severity: "high",
        created_at: new Date('2024-01-15')
    },
    {
        id: "tech-support",
        name: "Tech Support Scam",
        category: "Service Fraud",
        description: "Scammers pose as technical support to gain remote access to computers or steal money.",
        warning_signs: "Unsolicited calls about computer problems, requests for remote access, pressure to act immediately, requests for payment",
        example: "Cold call claiming your computer is infected and needs immediate fixing for a fee.",
        prevention_tips: "Never give remote access to unsolicited callers, verify identity independently, hang up and call official support",
        severity: "high",
        created_at: new Date('2024-01-20')
    },
    {
        id: "romance-scam",
        name: "Romance Scam",
        category: "Relationship Fraud",
        description: "Criminals create fake romantic relationships online to manipulate victims into sending money.",
        warning_signs: "Professes love quickly, avoids meeting in person, has emergencies requiring money, limited photos, stories don't add up",
        example: "Online romantic interest who needs money for a family emergency or travel expenses to meet you.",
        prevention_tips: "Be cautious of online relationships, never send money to someone you haven't met, verify identity through video calls",
        severity: "medium",
        created_at: new Date('2024-01-25')
    },
    {
        id: "investment-crypto",
        name: "Investment/Cryptocurrency Scam",
        category: "Financial Fraud",
        description: "Fraudulent investment opportunities promising unrealistic returns, often involving cryptocurrency.",
        warning_signs: "Guaranteed high returns, pressure to invest quickly, unlicensed sellers, complex fee structures, celebrity endorsements",
        example: "Social media ad promising to double your cryptocurrency investment in 30 days with celebrity endorsement.",
        prevention_tips: "Research investments thoroughly, verify licenses, be skeptical of guaranteed returns, check regulatory warnings",
        severity: "high",
        created_at: new Date('2024-02-01')
    },
    {
        id: "shopping-scam",
        name: "Online Shopping Scam",
        category: "E-commerce Fraud",
        description: "Fake online stores that take payment but never deliver goods, or sell counterfeit items.",
        warning_signs: "Prices too good to be true, no contact information, poor website design, no customer reviews, payment only by wire transfer",
        example: "Website selling designer goods at 90% discount with no return policy or customer service contact.",
        prevention_tips: "Shop from reputable retailers, check reviews and ratings, use secure payment methods with buyer protection",
        severity: "medium",
        created_at: new Date('2024-02-05')
    }
];

// === ANALYSIS HISTORY MANAGER === //
class AnalysisHistory {
    constructor() {
        this.storageKey = 'scamguard_analysis_history';
        this.maxEntries = 50;
    }

    // FIXED: Better error handling and validation
    addAnalysis(contentType, content, result) {
        try {
            if (!contentType || !content || !result) {
                throw new Error('Missing required parameters for analysis history');
            }

            const history = this.getHistory();
            const analysis = {
                id: this._generateId(),
                content_type: contentType,
                content: this._truncateContent(content, 100),
                risk_level: result.level || 'unknown',
                risk_score: result.score || 0,
                detected_patterns: result.factors || [],
                analysis_details: result.details || 'No details available',
                created_at: new Date().toISOString(),
                user_agent: this._getUserAgent()
            };

            history.unshift(analysis);
            
            // Keep only the last maxEntries
            if (history.length > this.maxEntries) {
                history.splice(this.maxEntries);
            }
            
            this._saveHistory(history);
            return analysis;
        } catch (error) {
            console.error('Error adding analysis to history:', error);
            return null;
        }
    }

    // FIXED: Better error handling for localStorage
    getHistory() {
        try {
            const stored = localStorage.getItem(this.storageKey);
            return stored ? JSON.parse(stored) : [];
        } catch (error) {
            console.error('Error loading analysis history:', error);
            return [];
        }
    }

    // ADDED: Get recent analyses with limit
    getRecentAnalyses(limit = 5) {
        return this.getHistory().slice(0, limit);
    }

    // ADDED: Search functionality
    searchHistory(query) {
        if (!query || query.trim() === '') return this.getHistory();
        
        const searchTerm = query.toLowerCase().trim();
        return this.getHistory().filter(analysis => 
            analysis.content.toLowerCase().includes(searchTerm) ||
            analysis.content_type.toLowerCase().includes(searchTerm) ||
            analysis.risk_level.toLowerCase().includes(searchTerm)
        );
    }

    // ADDED: Get statistics
    getStatistics() {
        const history = this.getHistory();
        if (history.length === 0) return null;

        const stats = {
            total_analyses: history.length,
            risk_distribution: {
                high: history.filter(a => a.risk_level === 'high').length,
                medium: history.filter(a => a.risk_level === 'medium').length,
                low: history.filter(a => a.risk_level === 'low').length
            },
            content_types: {
                url: history.filter(a => a.content_type === 'url').length,
                email: history.filter(a => a.content_type === 'email').length,
                message: history.filter(a => a.content_type === 'message').length
            },
            average_score: Math.round(history.reduce((sum, a) => sum + a.risk_score, 0) / history.length)
        };

        return stats;
    }

    clearHistory() {
        try {
            localStorage.removeItem(this.storageKey);
            return true;
        } catch (error) {
            console.error('Error clearing history:', error);
            return false;
        }
    }

    // ADDED: Helper methods
    _generateId() {
        return Date.now().toString(36) + Math.random().toString(36).substr(2);
    }

    _truncateContent(content, maxLength) {
        return content.length > maxLength ? content.slice(0, maxLength) + '...' : content;
    }

    _getUserAgent() {
        return typeof navigator !== 'undefined' ? navigator.userAgent : 'Unknown';
    }

    _saveHistory(history) {
        try {
            localStorage.setItem(this.storageKey, JSON.stringify(history));
        } catch (error) {
            console.error('Error saving history:', error);
            // If storage is full, try removing old entries
            if (error.name === 'QuotaExceededError') {
                const reducedHistory = history.slice(0, Math.floor(this.maxEntries / 2));
                localStorage.setItem(this.storageKey, JSON.stringify(reducedHistory));
            }
        }
    }
}

// === SEARCH FUNCTIONALITY === //
function searchScamTypes(query) {
    if (!query || query.trim() === '') return SCAM_TYPES;

    const searchTerm = query.toLowerCase().trim();
    return SCAM_TYPES.filter(scam => 
        scam.name.toLowerCase().includes(searchTerm) ||
        scam.description.toLowerCase().includes(searchTerm) ||
        scam.warning_signs.toLowerCase().includes(searchTerm) ||
        scam.prevention_tips.toLowerCase().includes(searchTerm) ||
        scam.category.toLowerCase().includes(searchTerm)
    );
}

// === EDUCATIONAL CONTENT === //
const EDUCATIONAL_CONTENT = {
    quickTips: [
        "Never share personal information via email or phone",
        "Verify URLs before clicking suspicious links",
        "Be skeptical of urgent or time-sensitive requests",
        "Contact organizations directly using official numbers",
        "Be cautious of unusual payment methods",
        "Discuss suspicious communications with trusted people",
        "Keep software and browsers updated",
        "Use strong, unique passwords with 2FA"
    ],
    
    redFlags: [
        "Requests for immediate action or payment",
        "Unsolicited contact about problems or prizes",
        "Pressure to keep communication secret",
        "Requests for remote computer access",
        "Payment via gift cards, wire transfers, or cryptocurrency",
        "Too-good-to-be-true offers or guarantees",
        "Poor grammar, spelling, or generic greetings",
        "Urgent threats about account suspension or legal action"
    ],
    
    greenFlags: [
        "Official contact information and websites",
        "Professional communication and branding",
        "No pressure for immediate decisions",
        "Secure payment methods with buyer protection",
        "Clear terms of service and refund policies",
        "Verifiable business registration and licenses",
        "Positive reviews from independent sources",
        "Proper SSL certificates and security indicators"
    ],
    
    actionSteps: [
        { step: 1, title: "Stop & Don't Respond", description: "Don't click links, provide info, or send money.", color: "danger" },
        { step: 2, title: "Verify Independently", description: "Contact organization directly using official info.", color: "warning" },
        { step: 3, title: "Report the Scam", description: "Report to authorities to protect others.", color: "success" }
    ],
    
    reportingResources: [
        { name: "FTC Fraud Reports", url: "https://reportfraud.ftc.gov/", icon: "external-link", description: "Report fraud to the Federal Trade Commission" },
        { name: "FBI IC3", url: "https://www.ic3.gov/", icon: "external-link", description: "Internet Crime Complaint Center" },
        { name: "FTC Scam Alerts", url: "https://www.consumer.ftc.gov/scam-alerts", icon: "external-link", description: "Stay updated on latest scam alerts" }
    ]
};

// === EXPORT FOR USE === //
// Export for use in both browser and Node.js environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SCAM_PATTERNS,
        DOMAIN_LISTS,
        SCAM_TYPES,
        AnalysisHistory,
        searchScamTypes,
        EDUCATIONAL_CONTENT
    };
} else if (typeof window !== 'undefined') {
    // Browser environment
    window.SCAM_PATTERNS = SCAM_PATTERNS;
    window.DOMAIN_LISTS = DOMAIN_LISTS;
    window.SCAM_TYPES = SCAM_TYPES;
    window.AnalysisHistory = AnalysisHistory;
    window.searchScamTypes = searchScamTypes;
    window.EDUCATIONAL_CONTENT = EDUCATIONAL_CONTENT;
}
