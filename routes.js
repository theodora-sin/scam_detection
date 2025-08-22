// Scam Analyzer Core Engine
class ScamAnalyzer {
    constructor() {
        this.urlPatterns = [
            { pattern: /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly/i, description: 'Shortened URL', score: 20 },
            { pattern: /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/, description: 'IP Address instead of domain', score: 30 },
            { pattern: /(paypal|amazon|microsoft|apple|google).*-.*\.com/i, description: 'Suspicious domain mimicking legitimate service', score: 40 },
            { pattern: /[a-z0-9]{8,}\.(tk|ml|ga|cf)/i, description: 'Free domain hosting', score: 25 },
            { pattern: /(secure|verify|update|confirm).*account/i, description: 'Account security keywords', score: 15 },
            { pattern: /\d{4,}-\d{4,}-\d{4,}/, description: 'Suspicious subdomain pattern', score: 20 }
        ];
        
        this.emailPatterns = [
            { pattern: /urgent|immediate|act now|limited time|expires today/i, description: 'Urgency tactics', score: 25 },
            { pattern: /verify your account|suspend|locked|frozen/i, description: 'Account threat language', score: 30 },
            { pattern: /click here|download now|claim your prize/i, description: 'Suspicious call-to-action', score: 20 },
            { pattern: /winner|congratulations|lottery|prize/i, description: 'Prize/lottery scam language', score: 35 },
            { pattern: /wire transfer|western union|moneygram|bitcoin/i, description: 'Unusual payment methods', score: 40 },
            { pattern: /dear (customer|sir|madam)/i, description: 'Generic greeting', score: 15 },
            { pattern: /[A-Z]{3,}\s+[A-Z]{3,}\s+[A-Z]{3,}/, description: 'Excessive capitalization', score: 10 },
            { pattern: /(\$|€|£)\s*\d{4,}/, description: 'Large money amounts', score: 20 },
            { pattern: /@[a-z0-9-]+\.(tk|ml|ga|cf|biz)/i, description: 'Suspicious sender domain', score: 30 }
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
        riskScore += this._checkPatterns(url, this.legitimatePatterns, []);
        
        return this._formatResult(riskScore, detectedPatterns, url, 'URL');
    }

    _analyzeEmail(emailContent) {
        let riskScore = 0;
        const detectedPatterns = [];
        
        riskScore += this._checkPatterns(emailContent, this.emailPatterns, detectedPatterns);
        riskScore += this._checkPatterns(emailContent, this.legitimatePatterns, []);
        
        return this._formatResult(riskScore, detectedPatterns, emailContent, 'Email');
    }

    _analyzeMessage(message) {
        let riskScore = 0;
        const detectedPatterns = [];
        
        riskScore += this._checkPatterns(message, this.messagePatterns, detectedPatterns);
        riskScore += this._checkPatterns(message, this.legitimatePatterns, []);
        
        return this._formatResult(riskScore, detectedPatterns, message, 'Message');
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
        const finalScore = Math.max(0, riskScore);
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
            
            localStorage.setItem(this.storageKey, JSON.stringify(history));
            return analysis;
        } catch (error) {
            console.error('Error adding analysis to history:', error);
            return null;
        }
    }

    getHistory() {
        try {
            const stored = localStorage.getItem(this.storageKey);
            return stored ? JSON.parse(stored) : [];
        } catch (error) {
            console.error('Error loading analysis history:', error);
            return [];
        }
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
}
