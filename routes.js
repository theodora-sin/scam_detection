// Scam Analyzer Core Engine - FIXED VERSION
class ScamAnalyzer {
    constructor() {
        // --- UPDATED URL PATTERNS WITH HIGHER SCORES ---
        this.urlPatterns = [
            { pattern: /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly/i, description: 'Shortened URL', score: 30 },
            { pattern: /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/, description: 'IP Address instead of domain', score: 40 },
            { pattern: /(paypal|amazon|microsoft|apple|google).*-.*\.com/i, description: 'Suspicious domain mimicking legitimate service', score: 50 },
            { pattern: /[a-z0-9]{8,}\.(tk|ml|ga|cf|xyz)/i, description: 'Free or suspicious domain hosting', score: 35 },
            { pattern: /(secure|verify|update|confirm).*account/i, description: 'Account security keywords', score: 30 },
            { pattern: /\d{4,}-\d{4,}-\d{4,}/, description: 'Suspicious subdomain pattern', score: 25 },
            { pattern: /xn--/i, description: 'Punycode URL (potential impersonation)', score: 45 }
        ];
        
        // --- UPDATED EMAIL PATTERNS WITH HIGHER SCORES ---
        this.emailPatterns = [
            { pattern: /urgent|immediate|act now|limited time|expires today/i, description: 'Urgency tactics', score: 30 },
            { pattern: /verify your account|suspend|locked|frozen/i, description: 'Account threat language', score: 35 },
            { pattern: /click here|download now|claim your prize/i, description: 'Suspicious call-to-action', score: 25 },
            { pattern: /winner|congratulations|lottery|prize/i, description: 'Prize/lottery scam language', score: 35 },
            { pattern: /wire transfer|western union|moneygram|bitcoin/i, description: 'Unusual payment methods', score: 40 },
            { pattern: /dear (customer|sir|madam)/i, description: 'Generic greeting', score: 15 },
            { pattern: /[A-Z]{3,}\s+[A-Z]{3,}\s+[A-Z]{3,}/, description: 'Excessive capitalization', score: 10 },
            { pattern: /(\$|€|£)\s*\d{4,}/, description: 'Large money amounts', score: 20 },
            { pattern: /@[a-z0-9-]+\.(tk|ml|ga|cf|biz)/i, description: 'Suspicious sender domain', score: 35 }
        ];
        
        this.messagePatterns = [
            { pattern: /romance|love|heart|marry|relationship/i, description: 'Romance scam language', score: 25 },
            { pattern: /investment|profit|return|guarantee|double/i, description: 'Investment scam language', score: 30 },
            { pattern: /tech support|computer|virus|infected|microsoft/i, description: 'Tech support scam', score: 35 },
            { pattern: /social security|ssn|government|irs|arrest/i, description: 'Government impersonation', score: 40 },
            { pattern: /emergency|hospital|accident|help/i, description: 'Emergency scam tactics', score: 25 },
            { pattern: /inheritance|beneficiary|estate|attorney/i, description: 'Inheritance scam', score: 35 },
            { pattern: /(whatsapp|telegram)\s*(chat|message|contact)/i, description: 'Suspicious communication platform', score: 20 }
        ];
        
        this.legitimatePatterns = [
            { pattern: /https:\/\/.*\.gov\//i, description: 'Government website', score: -20 },
            { pattern: /https:\/\/.*\.(edu|org)\//i, description: 'Educational/non-profit domain', score: -10 },
            { pattern: /contact us|customer service|help center/i, description: 'Customer service language', score: -5 },
            { pattern: /privacy policy|terms of service|unsubscribe/i, description: 'Legitimate website elements', score: -10 }
        ];

        // Initialize dictionary check (simplified without external dependency)
        this.commonWords = new Set([
            'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i', 'it', 'for', 'not', 'on', 
            'with', 'he', 'as', 'you', 'do', 'at', 'this', 'but', 'his', 'by', 'from', 'they', 'we', 
            'say', 'her', 'she', 'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their',
            'what', 'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go', 'me', 'when',
            'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know', 'take', 'people', 'into',
            'year', 'your', 'good', 'some', 'could', 'them', 'see', 'other', 'than', 'then', 'now',
            'look', 'only', 'come', 'its', 'over', 'think', 'also', 'back', 'after', 'use', 'two',
            'how', 'our', 'work', 'first', 'well', 'way', 'even', 'new', 'want', 'because', 'any',
            'these', 'give', 'day', 'most', 'us'
        ]);
    }

    analyzeContent(content, contentType) {
        try {
            if (!content || !contentType) {
                throw new Error('Content and content type are required');
            }

            switch (contentType.toLowerCase()) {
                case 'url':
                    return this._analyzeUrl(content);
                case 'email':
                    return this._analyzeEmail(content);
                case 'message':
                    return this._analyzeMessage(content);
                default:
                    throw new Error(`Unsupported content type: ${contentType}`);
            }
        } catch (error) {
            console.error('Analysis error:', error);
            return {
                level: 'unknown',
                score: 0,
                factors: [],
                details: `Error during analysis: ${error.message}`,
                timestamp: new Date().toISOString()
            };
        }
    }

    _analyzeUrl(url) {
        let riskScore = 0;
        const detectedPatterns = [];
        
        try {
            const urlObj = new URL(url);
            if (!urlObj.protocol.startsWith('http')) {
                throw new Error('Invalid protocol');
            }
        } catch (error) {
            return {
                level: 'high',
                score: 100,
                factors: ['Invalid URL format'],
                details: 'The provided URL is not properly formatted or uses an invalid protocol.',
                timestamp: new Date().toISOString()
            };
        }
        
        riskScore += this._checkPatterns(url, this.urlPatterns, detectedPatterns);
        riskScore -= this._checkPatterns(url, this.legitimatePatterns, []);
        
        // Add character analysis
        const charAnalysis = this._analyzeCharacterSets(url);
        riskScore += charAnalysis.score;
        detectedPatterns.push(...charAnalysis.factors);
        
        return this._formatResult(riskScore, detectedPatterns, url, 'URL');
    }

    _analyzeEmail(emailContent) {
        let riskScore = 0;
        const detectedPatterns = [];
        
        // Original pattern check
        riskScore += this._checkPatterns(emailContent, this.emailPatterns, detectedPatterns);
        riskScore -= this._checkPatterns(emailContent, this.legitimatePatterns, []);
        
        // Add text quality analysis
        const qualityAnalysis = this._analyzeTextQuality(emailContent);
        riskScore += qualityAnalysis.score;
        detectedPatterns.push(...qualityAnalysis.factors);
        
        // Character analysis
        const charAnalysis = this._analyzeCharacterSets(emailContent);
        riskScore += charAnalysis.score;
        detectedPatterns.push(...charAnalysis.factors);

        return this._formatResult(riskScore, detectedPatterns, emailContent, 'Email');
    }

    _analyzeMessage(message) {
        let riskScore = 0;
        const detectedPatterns = [];
        
        // Original pattern check
        riskScore += this._checkPatterns(message, this.messagePatterns, detectedPatterns);
        riskScore -= this._checkPatterns(message, this.legitimatePatterns, []);
        
        // Add text quality analysis
        const qualityAnalysis = this._analyzeTextQuality(message);
        riskScore += qualityAnalysis.score;
        detectedPatterns.push(...qualityAnalysis.factors);

        // Character analysis
        const charAnalysis = this._analyzeCharacterSets(message);
        riskScore += charAnalysis.score;
        detectedPatterns.push(...charAnalysis.factors);
        
        return this._formatResult(riskScore, detectedPatterns, message, 'Message');
    }

    // --- NEW METHOD for Spelling/Grammar Analysis (simplified) ---
    _analyzeTextQuality(content) {
        if (!content || typeof content !== 'string') {
            return { score: 0, factors: [] };
        }

        const words = content.toLowerCase()
            .replace(/[.,\/#!$%\^&\*;:{}=\-_`~()]/g, "")
            .split(/\s+/)
            .filter(word => word.length > 2);
        
        if (words.length === 0) {
            return { score: 0, factors: [] };
        }

        // Simple spelling check using common words
        const misspelledWords = words.filter(word => !this.commonWords.has(word));
        const errorDensity = misspelledWords.length / words.length;
        
        let score = 0;
        let factors = [];

        if (errorDensity > 0.7) { // If more than 70% of words are not in common words list
            score = 40;
            factors.push(`Extremely poor text quality (${misspelledWords.length} uncommon words)`);
        } else if (errorDensity > 0.5) { // If more than 50% of words are not common
            score = 25;
            factors.push(`Poor text quality detected (${misspelledWords.length} uncommon words)`);
        }
        
        // Check for excessive capitalization
        const capsCount = (content.match(/[A-Z]/g) || []).length;
        const capsRatio = capsCount / content.length;
        if (capsRatio > 0.3 && content.length > 20) {
            score += 20;
            factors.push('Excessive capitalization detected');
        }
        
        return { score, factors };
    }

    // --- CHARACTER SET ANALYSIS ---
    _analyzeCharacterSets(content) {
        if (!content) return { score: 0, factors: [] };

        // Check for mixed character sets (potential homograph attack)
        const hasLatin = /[a-zA-Z]/.test(content);
        const hasCyrillic = /[\u0400-\u04FF]/.test(content);
        const hasGreek = /[\u0370-\u03FF]/.test(content);
        const hasArabic = /[\u0600-\u06FF]/.test(content);

        let mixedSets = 0;
        let factors = [];
        
        if (hasLatin) mixedSets++;
        if (hasCyrillic) mixedSets++;
        if (hasGreek) mixedSets++;
        if (hasArabic) mixedSets++;

        if (mixedSets > 1) {
            return {
                score: 50,
                factors: ['Mixed character sets detected (potential homograph attack)']
            };
        }
        
        return { score: 0, factors: [] };
    }

    _checkPatterns(content, patterns, detectedPatterns) {
        let score = 0;
        for (const { pattern, description, score: patternScore } of patterns) {
            if (pattern.test(content)) {
                score += patternScore;
                if (patternScore > 0) {
                    detectedPatterns.push(description);
                }
            }
        }
        return score;
    }

    _formatResult(riskScore, detectedPatterns, content, contentType) {
        const finalScore = Math.max(0, Math.min(100, riskScore)); // Clamp between 0-100
        const level = this._calculateRiskLevel(finalScore);
        
        return {
            level,
            score: finalScore,
            factors: detectedPatterns,
            details: this._generateAnalysisDetails(contentType, content, finalScore, detectedPatterns),
            timestamp: new Date().toISOString()
        };
    }

    _calculateRiskLevel(riskScore) {
        if (riskScore >= 60) return 'high';
        if (riskScore >= 30) return 'medium';
        return 'low';
    }

    _generateAnalysisDetails(contentType, content, riskScore, patterns) {
        let details = `${contentType} Analysis Summary:\n\n`;
        details += `Risk Score: ${riskScore}/100\n`;
        details += `Risk Level: ${this._calculateRiskLevel(riskScore).toUpperCase()}\n\n`;
        
        if (patterns.length > 0) {
            details += "Risk Indicators Found:\n";
            patterns.forEach(pattern => details += `• ${pattern}\n`);
        } else {
            details += "No specific risk indicators detected.\n";
        }
        
        details += "\nRecommendations:\n";
        if (riskScore >= 60) {
            details += "• HIGH RISK: Avoid this content\n• Do not interact or provide information\n• Report if received unsolicited";
        } else if (riskScore >= 30) {
            details += "• MEDIUM RISK: Exercise caution\n• Verify source independently\n• Avoid sharing personal information";
        } else {
            details += "• LOW RISK: Content appears relatively safe\n• Still exercise normal security practices\n• Verify authenticity for important matters";
        }
        
        return details;
    }
}

// Analysis History Storage
class AnalysisHistory {
    constructor() {
        this.storageKey = 'scamguard_analysis_history';
        this.maxEntries = 50;
    }

    addAnalysis(contentType, content, result) {
        try {
            const history = this.getHistory();
            const analysis = {
                id: Date.now().toString(36) + Math.random().toString(36).substr(2),
                content_type: contentType,
                content: content.length > 100 ? content.slice(0, 100) + '...' : content,
                risk_level: result.level || 'unknown',
                risk_score: result.score || 0,
                detected_patterns: result.factors || [],
                analysis_details: result.details || 'No details available',
                created_at: new Date().toISOString()
            };

            history.unshift(analysis);
            
            if (history.length > this.maxEntries) {
                history.splice(this.maxEntries);
            }
            
            // Use in-memory storage instead of localStorage to avoid browser restrictions
            this._memoryStorage = history;
            
            return analysis;
        } catch (error) {
            console.error('Error adding analysis to history:', error);
            return null;
        }
    }

    getHistory() {
        try {
            // Try localStorage first, fallback to memory storage
            const stored = localStorage.getItem(this.storageKey);
            if (stored) {
                return JSON.parse(stored);
            }
            return this._memoryStorage || [];
        } catch (error) {
            console.error('Error loading analysis history:', error);
            return this._memoryStorage || [];
        }
    }

    clearHistory() {
        try {
            localStorage.removeItem(this.storageKey);
            this._memoryStorage = [];
            return true;
        } catch (error) {
            console.error('Error clearing history:', error);
            this._memoryStorage = [];
            return true; // Still return true since memory was cleared
        }
    }

    // Save to localStorage when possible
    _saveToStorage(history) {
        try {
            localStorage.setItem(this.storageKey, JSON.stringify(history));
        } catch (error) {
            console.warn('Could not save to localStorage, using memory storage only');
        }
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ScamAnalyzer, AnalysisHistory };
} else if (typeof window !== 'undefined') {
    window.ScamAnalyzer = ScamAnalyzer;
    window.AnalysisHistory = AnalysisHistory;
}
