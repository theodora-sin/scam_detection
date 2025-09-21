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
                throw new Error('Content and content type are required');
            }

            let baseScore = 0;
            const detectedPatterns = [];
            const analysisDetails = [];

            // Phase 1: Pattern Matching with Weights
            const patternResult = this._analyzePatterns(content, contentType, detectedPatterns);
            baseScore += patternResult.score;
            analysisDetails.push(...patternResult.details);

            // Phase 2: Contextual Analysis
            const contextResult = this._analyzeContext(content, contentType, detectedPatterns);
            baseScore += contextResult.score;
            analysisDetails.push(...contextResult.details);

            // Phase 3: Text Quality Analysis
            const qualityResult = this._analyzeTextQuality(content, detectedPatterns);
            baseScore += qualityResult.score;
            analysisDetails.push(...qualityResult.details);

            // Phase 4: Content-Specific Analysis
            const specificResult = this._analyzeContentSpecific(content, contentType, detectedPatterns);
            baseScore += specificResult.score;
            analysisDetails.push(...specificResult.details);

            // Phase 5: Legitimate Pattern Reduction
            const legitimateResult = this._analyzeLegitimatePatterns(content, detectedPatterns);
            baseScore += legitimateResult.score; // This will be negative
            analysisDetails.push(...legitimateResult.details);

            // Final Score Calculation
            const finalScore = this._calculateFinalScore(baseScore, detectedPatterns);
            const riskLevel = this._calculateRiskLevel(finalScore);

            return {
                level: riskLevel,
                score: finalScore,
                factors: detectedPatterns,
                details: this._generateDetailedReport(contentType, finalScore, riskLevel, detectedPatterns, analysisDetails),
                recommendations: this._generateRecommendations(riskLevel, contentType, detectedPatterns),
                timestamp: new Date().toISOString(),
                analysisPhases: {
                    patternScore: patternResult.score,
                    contextScore: contextResult.score,
                    qualityScore: qualityResult.score,
                    specificScore: specificResult.score,
                    legitimateScore: legitimateResult.score,
                    finalScore: finalScore
                }
            };

        } catch (error) {
            console.error('Analysis error:', error);
            return {
                level: 'unknown',
                score: 0,
                factors: ['Analysis error occurred'],
                details: `Error: ${error.message}`,
                recommendations: ['Please try again with valid content'],
                timestamp: new Date().toISOString()
            };
        }
    }

    _analyzePatterns(content, contentType, detectedPatterns) {
        let score = 0;
        const details = [];
        let patterns = [];

        // Select appropriate patterns
        switch (contentType.toLowerCase()) {
            case 'url':
                patterns = this.urlPatterns;
                break;
            case 'email':
                patterns = this.emailPatterns;
                break;
            case 'message':
                patterns = this.messagePatterns;
                break;
            case 'phone':
                patterns = this.phonePatterns;
                break;
            default:
                patterns = [...this.emailPatterns, ...this.messagePatterns];
        }

        // Enhanced pattern matching with weights and multipliers
        patterns.forEach(({ pattern, description, score: baseScore, weight }) => {
            const matches = content.match(pattern) || [];
            if (matches.length > 0) {
                // Apply weight multiplier
                const weightMultiplier = this.patternWeights[weight] || 1.0;
                
                // Apply frequency multiplier (diminishing returns)
                const frequencyMultiplier = matches.length > 1 ? 
                    1 + Math.log(matches.length) * 0.3 : 1;
                
                const adjustedScore = Math.round(baseScore * weightMultiplier * frequencyMultiplier);
                score += adjustedScore;
                
                const patternDescription = matches.length > 1 ? 
                    `${description} (${matches.length}x)` : description;
                detectedPatterns.push(patternDescription);
                
                details.push(`Pattern: ${description} | Weight: ${weight} | Score: +${adjustedScore}`);
            }
        });

        return { score, details };
    }

    _analyzeContext(content, contentType, detectedPatterns) {
        let score = 0;
        const details = [];

        // Content length analysis
        if (content.length < this.contextFactors.tooShort.threshold) {
            score += this.contextFactors.tooShort.score;
            detectedPatterns.push(this.contextFactors.tooShort.description);
            details.push(`Context: Content too short (${content.length} chars) | Score: +${this.contextFactors.tooShort.score}`);
        } else if (content.length > this.contextFactors.tooLong.threshold) {
            score += this.contextFactors.tooLong.score;
            detectedPatterns.push(this.contextFactors.tooLong.description);
            details.push(`Context: Content too long (${content.length} chars) | Score: +${this.contextFactors.tooLong.score}`);
        }

        // Character set analysis
        const charAnalysis = this._analyzeCharacterSets(content);
        score += charAnalysis.score;
        detectedPatterns.push(...charAnalysis.factors);
        details.push(...charAnalysis.details);

        // URL-specific context analysis
        if (contentType === 'url') {
            const urlContext = this._analyzeUrlContext(content);
            score += urlContext.score;
            detectedPatterns.push(...urlContext.factors);
            details.push(...urlContext.details);
        }

        return { score, details };
    }

    _analyzeTextQuality(content, detectedPatterns) {
        let score = 0;
        const details = [];

        const words = content.toLowerCase()
            .replace(/[^\w\s]/g, ' ')
            .split(/\s+/)
            .filter(word => word.length > 2);

        if (words.length === 0) {
            return { score: 0, details: [] };
        }

        // Vocabulary analysis
        const uncommonWords = words.filter(word => !this.commonWords.has(word));
        const vocabularyRatio = uncommonWords.length / words.length;

        if (vocabularyRatio > 0.8) {
            score += 35;
            detectedPatterns.push('Very poor vocabulary/spelling detected');
            details.push(`Text Quality: High uncommon word ratio (${Math.round(vocabularyRatio * 100)}%) | Score: +35`);
        } else if (vocabularyRatio > 0.6) {
            score += 25;
            detectedPatterns.push('Poor text quality detected');
            details.push(`Text Quality: Moderate uncommon word ratio (${Math.round(vocabularyRatio * 100)}%) | Score: +25`);
        }

        // Capitalization analysis
        const capsCount = (content.match(/[A-Z]/g) || []).length;
        const capsRatio = content.length > 0 ? capsCount / content.length : 0;

        if (capsRatio > 0.4 && content.length > 20) {
            score += 30;
            detectedPatterns.push('Excessive capitalization (shouting)');
            details.push(`Text Quality: Excessive caps ratio (${Math.round(capsRatio * 100)}%) | Score: +30`);
        } else if (capsRatio > 0.2 && content.length > 50) {
            score += 20;
            detectedPatterns.push('High capitalization detected');
            details.push(`Text Quality: High caps ratio (${Math.round(capsRatio * 100)}%) | Score: +20`);
        }

        // Repetitive pattern analysis
        const repetitivePatterns = [
            /(.)\1{4,}/, // Same character 5+ times
            /(\w+)\s+\1\s+\1/, // Same word repeated 3+ times
            /!{4,}|\?{4,}|\.{5,}/ // Excessive punctuation
        ];

        repetitivePatterns.forEach(pattern => {
            if (pattern.test(content)) {
                score += 25;
                detectedPatterns.push('Repetitive or excessive patterns detected');
                details.push('Text Quality: Repetitive patterns found | Score: +25');
            }
        });

        return { score, details };
    }

    _analyzeContentSpecific(content, contentType, detectedPatterns) {
        let score = 0;
        const details = [];

        switch (contentType.toLowerCase()) {
            case 'email':
                const emailAnalysis = this._analyzeEmailStructure(content);
                score += emailAnalysis.score;
                detectedPatterns.push(...emailAnalysis.factors);
                details.push(...emailAnalysis.details);
                break;
                
            case 'url':
                const urlAnalysis = this._analyzeUrlStructure(content);
                score += urlAnalysis.score;
                detectedPatterns.push(...urlAnalysis.factors);
                details.push(...urlAnalysis.details);
                break;
                
            case 'phone':
                const phoneAnalysis = this._analyzePhoneStructure(content);
                score += phoneAnalysis.score;
                detectedPatterns.push(...phoneAnalysis.factors);
                details.push(...phoneAnalysis.details);
                break;
        }

        return { score, details };
    }

    _analyzeCharacterSets(content) {
        let score = 0;
        const factors = [];
        const details = [];

        const characterSets = {
            latin: /[a-zA-Z]/.test(content),
            cyrillic: /[\u0400-\u04FF]/.test(content),
            greek: /[\u0370-\u03FF]/.test(content),
            arabic: /[\u0600-\u06FF]/.test(content),
            chinese: /[\u4E00-\u9FFF]/.test(content),
            japanese: /[\u3040-\u309F\u30A0-\u30FF]/.test(content)
        };

        const activeSets = Object.keys(characterSets).filter(set => characterSets[set]);

        if (activeSets.length > 1) {
            score = 35 + (activeSets.length - 2) * 15;
            factors.push(`Mixed character sets: ${activeSets.join(', ')} (homograph attack risk)`);
            details.push(`Character Sets: Mixed scripts detected (${activeSets.join(', ')}) | Score: +${score}`);
        }

        // Hidden Unicode characters
        const hiddenUnicode = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064]/.test(content);
        if (hiddenUnicode) {
            score += 45;
            factors.push('Hidden Unicode characters detected');
            details.push('Character Sets: Hidden Unicode characters found | Score: +45');
        }

        return { score, factors, details };
    }

    _analyzeUrlContext(url) {
        let score = 0;
        const factors = [];
        const details = [];

        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname.toLowerCase();
            const path = urlObj.pathname;

            // Domain analysis
            if (domain.length > 40) {
                score += 25;
                factors.push('Extremely long domain name');
                details.push(`URL Context: Very long domain (${domain.length} chars) | Score: +25`);
            }

            // Subdomain analysis
            const subdomains = domain.split('.');
            if (subdomains.length > 5) {
                score += 30;
                factors.push('Excessive subdomains detected');
                details.push(`URL Context: Too many subdomains (${subdomains.length}) | Score: +30`);
            }

            // Path traversal attempts
            if (path.includes('..')) {
                score += 50;
                factors.push('Path traversal attempt detected');
                details.push('URL Context: Path traversal detected | Score: +50');
            }

            // Query parameter analysis
            const paramString = urlObj.search;
            if (paramString.length > 300) {
                score += 20;
                factors.push('Excessively long query parameters');
                details.push(`URL Context: Long query params (${paramString.length} chars) | Score: +20`);
            }

        } catch (e) {
            // URL parsing failed - already handled in main analysis
        }

        return { score, factors, details };
    }

    _analyzeEmailStructure(content) {
        let score = 0;
        const factors = [];
        const details = [];

        // Check for standard email elements
        const hasSubject = /subject:/i.test(content);
        const hasFrom = /from:/i.test(content);
        const hasTo = /to:/i.test(content);

        if (!hasSubject && !hasFrom && !hasTo && content.length > 100) {
            score += 15;
            factors.push('Missing standard email headers');
            details.push('Email Structure: Missing standard headers | Score: +15');
        }

        // Check for suspicious HTML/formatting
        const hasHiddenText = /style\s*=\s*['"](color:\s*(white|#fff)|font-size:\s*0|display:\s*none)['"]/i.test(content);
        if (hasHiddenText) {
            score += 40;
            factors.push('Hidden text formatting detected');
            details.push('Email Structure: Hidden text detected | Score: +40');
        }

        // Multiple links analysis
        const urlMatches = content.match(/https?:\/\/[^\s]+/g) || [];
        if (urlMatches.length > 8) {
            score += 35;
            factors.push(`Excessive links detected (${urlMatches.length} links)`);
            details.push(`Email Structure: Too many links (${urlMatches.length}) | Score: +35`);
        }
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
