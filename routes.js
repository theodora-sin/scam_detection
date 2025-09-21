// Enhanced Scam Analyzer with Improved Risk Scoring System
class ScamAnalyzer {
    constructor() {
        // === WEIGHTED PATTERN CATEGORIES ===
        this.patternWeights = {
            critical: 1.5,    // Most dangerous patterns (multiplier)
            high: 1.2,        // High-risk patterns
            medium: 1.0,      // Standard patterns
            low: 0.8,         // Lower-risk patterns
            informational: 0.5 // Just informational
        };
        // === IMPROVED URL PATTERNS WITH WEIGHTED SCORING ===
        this.urlPatterns = [
            // CRITICAL THREATS (High multiplier)
            { pattern: /\.(exe|scr|bat|com|pif|vbs|jar|zip|rar)(\?|$)/i, description: 'Executable file in URL (CRITICAL)', score: 80, weight: 'critical' },
            { pattern: /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/, description: 'Raw IP address instead of domain', score: 60, weight: 'critical' },
            { pattern: /xn--/i, description: 'Punycode URL (homograph attack)', score: 70, weight: 'critical' },
            
            // HIGH RISK PATTERNS
            { pattern: /(payp[a4]l|[a4]m[a4]zon|micr0s0ft|[a4]pple|g[o0]{2}gle|f[a4]ceb[o0]{2}k|tw[i1]tter).*\.(com|net|org)/i, description: 'Brand typosquatting detected', score: 65, weight: 'high' },
            { pattern: /(bank|secure|login|account|verify|update|confirm).*-.*\.(com|net|org|biz)/i, description: 'Suspicious domain with security keywords', score: 55, weight: 'high' },
            { pattern: /[a-z0-9]{12,}\.(tk|ml|ga|cf|xyz|click)/i, description: 'Long random domain on suspicious TLD', score: 50, weight: 'high' },
            
            // MEDIUM RISK PATTERNS
            { pattern: /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|short\.link|is\.gd|buff\.ly|rebrand\.ly|cutt\.ly|tiny\.cc/i, description: 'URL shortening service', score: 35, weight: 'medium' },
            { pattern: /\.(tk|ml|ga|cf|xyz|click|download|bid|country|loan|win|review|racing|accountant)/i, description: 'Suspicious or free domain TLD', score: 40, weight: 'medium' },
            { pattern: /(secure|login|account|verify|update|confirm)\.[a-z0-9-]+\.(com|net)/i, description: 'Security-themed suspicious subdomain', score: 45, weight: 'medium' },
            { pattern: /:[0-9]{1,5}\//, description: 'Non-standard port number', score: 30, weight: 'medium' },
            
            // LOW RISK PATTERNS
            { pattern: /\d{4,}-\d{4,}-\d{4,}/, description: 'Unusual subdomain pattern', score: 25, weight: 'low' },
            { pattern: /\/+[a-z0-9]{15,}/i, description: 'Long random URL path', score: 20, weight: 'low' },
            { pattern: /redirect|redir|goto|link|click|ref/i, description: 'URL redirection indicators', score: 20, weight: 'low' },
            
            // INFORMATIONAL
            { pattern: /(%[0-9a-f]{2}){2,}/i, description: 'URL encoding detected', score: 15, weight: 'informational' },
            { pattern: /\?[a-z0-9]{10,}/i, description: 'Long query parameters', score: 15, weight: 'informational' }
        ];

        // === IMPROVED EMAIL PATTERNS WITH WEIGHTED SCORING ===
        this.emailPatterns = [
            // CRITICAL THREATS
            { pattern: /virus.*detected|malware.*found|computer.*infected|system.*compromised/i, description: 'Fake malware alert (CRITICAL)', score: 75, weight: 'critical' },
            { pattern: /embarrassing.*video|intimate.*photos|webcam.*recording|blackmail|extortion/i, description: 'Blackmail/extortion attempt (CRITICAL)', score: 85, weight: 'critical' },
            { pattern: /(open|view|download|execute) (attachment|document|file|invoice|receipt).*urgently?/i, description: 'Urgent malicious attachment request', score: 70, weight: 'critical' },
            
            // HIGH RISK PATTERNS
            { pattern: /suspended.*account|expired.*session|re.?activate.*now|re.?verify.*immediately/i, description: 'Account suspension phishing', score: 60, weight: 'high' },
            { pattern: /wire transfer|western union|moneygram|bitcoin|cryptocurrency|gift cards?|prepaid cards?/i, description: 'Unusual payment methods', score: 55, weight: 'high' },
            { pattern: /(million|thousand) (dollars?|euros?|pounds?)|inheritance.*\$.*million/i, description: 'Unrealistic large money claims', score: 65, weight: 'high' },
            { pattern: /(paypal|amazon|microsoft|apple|google|facebook|twitter|instagram).*security.*alert/i, description: 'Major service impersonation', score: 60, weight: 'high' },
            { pattern: /processing fee|handling fee|tax payment|transfer fee|activation fee/i, description: 'Advance fee fraud language', score: 55, weight: 'high' },
            
            // MEDIUM RISK PATTERNS
            { pattern: /urgent|immediate|act now|limited time|expires today|final notice|last chance/i, description: 'Urgency pressure tactics', score: 35, weight: 'medium' },
            { pattern: /verify your account|locked|frozen|blocked|deactivated|compromised/i, description: 'Account threat language', score: 40, weight: 'medium' },
            { pattern: /congratulations|winner|you.?(won|win)|lottery|jackpot|prize|reward/i, description: 'Prize/lottery scam language', score: 40, weight: 'medium' },
            { pattern: /click here|download now|claim your (prize|reward|money)|update (now|immediately)/i, description: 'Suspicious call-to-action', score: 35, weight: 'medium' },
            { pattern: /investment opportunity|guaranteed return|profit margin|roi|passive income/i, description: 'Investment scam language', score: 45, weight: 'medium' },
            
            // LOW RISK PATTERNS
            { pattern: /@[a-z0-9-]+\.(tk|ml|ga|cf|biz|click|download)/i, description: 'Email from suspicious domain', score: 30, weight: 'low' },
            { pattern: /dear (customer|sir|madam|friend|beneficiary)/i, description: 'Generic impersonal greeting', score: 20, weight: 'low' },
            { pattern: /(\$|€|£|¥)\s*\d{3,}/, description: 'Money amounts mentioned', score: 25, weight: 'low' },
            
            // INFORMATIONAL
            { pattern: /[A-Z]{4,}\s+[A-Z]{4,}\s+[A-Z]{4,}/, description: 'Excessive capitalization', score: 15, weight: 'informational' },
            { pattern: /!!!+|!!!.*!!!|\?\?\?+/i, description: 'Excessive punctuation', score: 10, weight: 'informational' }
        ];

        // === IMPROVED MESSAGE PATTERNS WITH WEIGHTED SCORING ===
        this.messagePatterns = [
            // CRITICAL THREATS
            { pattern: /remote.*access|teamviewer|anydesk|logmein|screen.*share|download.*software/i, description: 'Remote access scam (CRITICAL)', score: 80, weight: 'critical' },
            { pattern: /arrest.*warrant|legal.*action.*pending|court.*summons|jail.*time/i, description: 'Legal threat scam (CRITICAL)', score: 75, weight: 'critical' },
            { pattern: /social.*security.*suspended|ssn.*compromised|government.*investigation/i, description: 'SSN/Government threat scam', score: 70, weight: 'critical' },
            
            // HIGH RISK PATTERNS
            { pattern: /tech.*support|computer.*problem|virus.*detected|microsoft.*calling|apple.*support/i, description: 'Tech support scam', score: 55, weight: 'high' },
            { pattern: /forex|binary.*options|crypto.?trading|bitcoin.*investment|mining.*contract/i, description: 'High-risk investment schemes', score: 50, weight: 'high' },
            { pattern: /federal.*agency|homeland.*security|fbi|police.*department|irs.*agent/i, description: 'Law enforcement impersonation', score: 65, weight: 'high' },
            { pattern: /inheritance|will|estate|beneficiary|deceased.*relative|attorney.*contact/i, description: 'Inheritance fraud', score: 50, weight: 'high' },
            { pattern: /personal.*assistant|money.*transfer.*agent|payment.*processor.*job/i, description: 'Money laundering recruitment', score: 60, weight: 'high' },
            
            // MEDIUM RISK PATTERNS
            { pattern: /love|heart|soul.?mate|marry|marriage|relationship.*serious/i, description: 'Romance scam language', score: 35, weight: 'medium' },
            { pattern: /investment|profit.*guaranteed|double.*money|financial.*freedom/i, description: 'Investment scam tactics', score: 40, weight: 'medium' },
            { pattern: /emergency|hospital|accident|stranded.*need.*help|urgent.*help/i, description: 'Emergency assistance scam', score: 35, weight: 'medium' },
            { pattern: /won.*lottery|lottery.*winner|cash.*prize|sweepstakes.*winner/i, description: 'Lottery scam claims', score: 40, weight: 'medium' },
            { pattern: /charity|donation|disaster.*relief|children.*need.*help/i, description: 'Charity scam appeals', score: 30, weight: 'medium' },
            
            // LOW RISK PATTERNS
            { pattern: /(whatsapp|telegram|signal).*chat|move.*conversation.*to/i, description: 'Communication platform switch', score: 25, weight: 'low' },
            { pattern: /work.*from.*home|easy.*money|no.*experience.*required/i, description: 'Employment scam indicators', score: 20, weight: 'low' },
            { pattern: /widow|widower|military|soldier|deployed|overseas/i, description: 'Romance scam professions', score: 25, weight: 'low' },
            
            // INFORMATIONAL
            { pattern: /god.*bless|prayers|blessed|trust.*in.*god/i, description: 'Religious manipulation', score: 15, weight: 'informational' }
        ];

        // === PHONE NUMBER PATTERNS ===
        this.phonePatterns = [
            // CRITICAL
            { pattern: /^\+?(234|233|229|225|237|254)/, description: 'High-risk country code (West/East Africa)', score: 70, weight: 'critical' },
            
            // HIGH RISK
            { pattern: /^\+?1-?8(00|33|44|55|66|77|88|99)/, description: 'Common scam toll-free pattern', score: 50, weight: 'high' },
            { pattern: /^\+?(375|380|996|998)/, description: 'High-risk country codes (Eastern Europe)', score: 55, weight: 'high' },
            
            // MEDIUM RISK
            { pattern: /^\+?1-?[0-9]{3}-?000-?[0-9]{4}/, description: 'Suspicious number format', score: 35, weight: 'medium' },
            { pattern: /^(\+?1)?(555|888|777|666|999)/, description: 'Suspicious area codes', score: 30, weight: 'medium' }
        ];

        // === ENHANCED LEGITIMATE PATTERNS ===
        this.legitimatePatterns = [
            // Strong legitimacy indicators
            { pattern: /https:\/\/.*\.gov(\.[a-z]{2})?\//, description: 'Official government domain', score: -40, weight: 'critical' },
            { pattern: /https:\/\/(www\.)?(google|microsoft|apple|amazon|paypal|facebook|twitter|linkedin|github)\.com/i, description: 'Major legitimate service', score: -35, weight: 'high' },
            { pattern: /gdpr|ccpa|data.*protection|privacy.*policy.*compliant/i, description: 'Privacy regulation compliance', score: -30, weight: 'high' },
            
            // Medium legitimacy indicators  
            { pattern: /https:\/\/.*\.(edu|ac\.[a-z]{2})\//, description: 'Educational institution', score: -25, weight: 'medium' },
            { pattern: /unsubscribe|opt.?out|manage.*preferences/i, description: 'Legitimate opt-out options', score: -20, weight: 'medium' },
            { pattern: /customer.*service|help.*center|support.*team/i, description: 'Professional support language', score: -15, weight: 'medium' },
            
            // Light legitimacy indicators
            { pattern: /best.*regards|sincerely|kind.*regards|yours.*truly/i, description: 'Professional email closing', score: -10, weight: 'low' },
            { pattern: /invoice|receipt|order.*confirmation|shipping.*notification/i, description: 'Business communication', score: -10, weight: 'low' }
        ];

        // === CONTEXTUAL SCORING FACTORS ===
        this.contextFactors = {
            // Content length analysis
            tooShort: { threshold: 10, score: 20, description: 'Suspiciously short content' },
            tooLong: { threshold: 2000, score: 15, description: 'Excessively long content' },
            
            // Pattern density
            highDensity: { threshold: 0.1, score: 25, description: 'High suspicious pattern density' },
            
            // Character analysis
            nonAscii: { threshold: 0.3, score: 30, description: 'High non-ASCII character ratio' },
            mixedScripts: { score: 40, description: 'Mixed character scripts detected' }
        };

        // Enhanced common words dictionary
        this.commonWords = new Set([
            'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i', 'it', 'for', 'not', 'on',
            'with', 'he', 'as', 'you', 'do', 'at', 'this', 'but', 'his', 'by', 'from', 'they', 'we',
            'say', 'her', 'she', 'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their',
            'what', 'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go', 'me', 'when',
            'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know', 'take', 'people', 'into',
            'year', 'your', 'good', 'some', 'could', 'them', 'see', 'other', 'than', 'then', 'now',
            'look', 'only', 'come', 'its', 'over', 'think', 'also', 'back', 'after', 'use', 'two',
            'how', 'our', 'work', 'first', 'well', 'way', 'even', 'new', 'want', 'because', 'any',
            'these', 'give', 'day', 'most', 'us', 'is', 'water', 'been', 'call', 'who', 'oil', 'sit',
            // Extended common words
            'email', 'message', 'website', 'internet', 'computer', 'phone', 'account', 'password',
            'service', 'customer', 'support', 'help', 'contact', 'information', 'please', 'thank',
            'hello', 'dear', 'regards', 'sincerely', 'best', 'business', 'company', 'order', 'payment'
        ]);

        // Risk level thresholds (adjusted for better distribution)
        this.riskThresholds = {
            high: 65,    // Raised from 60
            medium: 35,  // Raised from 30
            low: 0
        };
    }

    analyzeContent(content, contentType) {
        try {
        if (!content || !contentType) {
            return this._formatResult(0, [], content || '', contentType || 'Unknown');
        }

        switch (contentType.toLowerCase()) {
            case 'url':
                return this._analyzeUrl(content);
            case 'email':
                return this._analyzeEmail(content);
            case 'message':
                return this._analyzeMessage(content);
            default:
                return this._formatResult(0, [], content, contentType);
        }
        } catch (error) {
            console.error('Analysis error:', error);
            return {
                level: 'unknown',
                score: 0,
                factors: [],
                details: `Error during analysis: ${error.message}`,
                timestamp: new Date().toISOString()
            }
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
        
        return this._formatResult(riskScore, detectedPatterns, url, 'URL');
    }

    _analyzeEmail(emailContent) {
        let riskScore = 0;
        const detectedPatterns = [];
        
    riskScore += this._checkPatterns(emailContent, this.emailPatterns, detectedPatterns);
    riskScore -= this._checkPatterns(emailContent, this.legitimatePatterns, []);
        
        return this._formatResult(riskScore, detectedPatterns, emailContent, 'Email');
    }

    _analyzeMessage(message) {
        let riskScore = 0;
        const detectedPatterns = [];
        
    riskScore += this._checkPatterns(message, this.messagePatterns, detectedPatterns);
    riskScore -= this._checkPatterns(message, this.legitimatePatterns, []);
        
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
            timestamp: new Date().toISOString(),
            // For UI compatibility:
            risk_level: level,
            risk_score: finalScore,
            detected_patterns: detectedPatterns
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
