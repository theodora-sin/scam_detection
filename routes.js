// Enhanced Scam Analyzer with Comprehensive Pattern Analysis
class ScamAnalyzer {
    constructor() {
        // === EXPANDED URL PATTERNS ===
        this.urlPatterns = [
            // Shortened URLs and URL shorteners
            { pattern: /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|short\.link|is\.gd|buff\.ly|rebrand\.ly|cutt\.ly|tiny\.cc/i, description: 'Shortened URL service', score: 30 },
            
            // IP addresses instead of domains
            { pattern: /https?:\/\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/, description: 'IP Address instead of domain', score: 45 },
            
            // Suspicious domain mimicking (typosquatting)
            { pattern: /(payp[a4]l|[a4]m[a4]zon|micr0s0ft|[a4]pple|g[o0]{2}gle|f[a4]ceb[o0]{2}k|tw[i1]tter).*\.(com|net|org)/i, description: 'Typosquatting - mimicking legitimate brand', score: 60 },
            { pattern: /(bank|secure|login|account|verify|update|confirm).*-.*\.(com|net|org|biz)/i, description: 'Suspicious domain with security keywords', score: 50 },
            
            // Free/suspicious hosting domains
            { pattern: /\.(tk|ml|ga|cf|xyz|click|download|bid|country|loan|win|review|racing|accountant)/i, description: 'Free or suspicious domain hosting', score: 40 },
            { pattern: /[a-z0-9]{8,}\.(tk|ml|ga|cf|xyz|click)/i, description: 'Long random domain on suspicious TLD', score: 50 },
            
            // Suspicious subdomains
            { pattern: /\d{4,}-\d{4,}-\d{4,}/, description: 'Suspicious subdomain pattern', score: 30 },
            { pattern: /(secure|login|account|verify|update|confirm)\.[a-z0-9-]+\.(com|net)/i, description: 'Security-themed suspicious subdomain', score: 45 },
            { pattern: /[a-z0-9]{10,}\.(com|net|org)/i, description: 'Very long domain name (often random)', score: 35 },
            
            // Punycode and internationalized domains
            { pattern: /xn--/i, description: 'Punycode URL (potential homograph attack)', score: 55 },
            
            // Suspicious URL structures
            { pattern: /\/+[a-z0-9]{20,}/i, description: 'Suspicious long random path', score: 25 },
            { pattern: /\?[a-z0-9]{15,}/i, description: 'Suspicious long query parameter', score: 20 },
            { pattern: /redirect|redir|goto|link|click|ref/i, description: 'URL redirection patterns', score: 25 },
            
            // Port numbers (unusual for normal websites)
            { pattern: /:[0-9]{1,5}\//, description: 'Non-standard port number', score: 30 },
            
            // Suspicious file extensions in URLs
            { pattern: /\.(exe|scr|bat|com|pif|vbs|jar|zip|rar)(\?|$)/i, description: 'Suspicious file extension in URL', score: 70 },
            
            // URL encoding abuse
            { pattern: /(%[0-9a-f]{2}){3,}/i, description: 'Excessive URL encoding (potential obfuscation)', score: 35 }
        ];

        // === EXPANDED EMAIL PATTERNS ===
        this.emailPatterns = [
            // Urgency and pressure tactics
            { pattern: /urgent|immediate|act now|limited time|expires today|final notice|last chance|time[\s-]?sensitive|deadline/i, description: 'Urgency and pressure tactics', score: 35 },
            { pattern: /within \d+ hours?|in \d+ minutes?|expires? (today|tomorrow|soon)/i, description: 'Time pressure with specific deadlines', score: 40 },
            
            // Account security threats
            { pattern: /verify your account|suspend|locked|frozen|blocked|deactivated|compromised|breach/i, description: 'Account threat language', score: 40 },
            { pattern: /unauthorized (access|login|activity)|suspicious (activity|login)|security alert/i, description: 'Fake security warnings', score: 45 },
            { pattern: /confirm your (identity|personal|account|payment)/i, description: 'Identity confirmation requests', score: 35 },
            
            // Suspicious call-to-action
            { pattern: /click here|download now|claim your (prize|reward|money)|update (now|immediately)/i, description: 'Suspicious call-to-action phrases', score: 30 },
            { pattern: /(open|view|download) (attachment|document|file|invoice|receipt)/i, description: 'Malicious attachment requests', score: 45 },
            
            // Prize/lottery scam language
            { pattern: /congratulations|winner|you.?(won|win)|lottery|jackpot|prize|reward|cash.?prize/i, description: 'Prize and lottery scam language', score: 40 },
            { pattern: /(million|thousand) (dollars?|euros?|pounds?)|inheritance.*million/i, description: 'Large money prize claims', score: 50 },
            
            // Payment and financial scams
            { pattern: /wire transfer|western union|moneygram|bitcoin|cryptocurrency|gift cards?|prepaid cards?/i, description: 'Unusual payment methods', score: 45 },
            { pattern: /processing fee|handling fee|tax payment|transfer fee|activation fee/i, description: 'Advance fee fraud language', score: 50 },
            { pattern: /refund|reimbursement|compensation.*available/i, description: 'Fake refund offers', score: 30 },
            
            // Generic/impersonal greetings
            { pattern: /dear (customer|sir|madam|friend|beneficiary|winner)/i, description: 'Generic impersonal greeting', score: 20 },
            { pattern: /dear valued (customer|client|member)/i, description: 'Generic valued customer greeting', score: 25 },
            
            // Poor grammar indicators
            { pattern: /[A-Z]{4,}\s+[A-Z]{4,}\s+[A-Z]{4,}/, description: 'Excessive capitalization', score: 15 },
            { pattern: /!!!+|!!!.*!!!|\?\?\?+/i, description: 'Excessive punctuation', score: 20 },
            
            // Money amounts
            { pattern: /(\$|€|£|¥)\s*\d{4,}/, description: 'Large money amounts mentioned', score: 25 },
            { pattern: /\d+\s*(million|billion)\s*(dollars?|euros?|pounds?)/i, description: 'Unrealistic large sums', score: 40 },
            
            // Suspicious sender domains
            { pattern: /@[a-z0-9-]+\.(tk|ml|ga|cf|biz|click|download)/i, description: 'Email from suspicious domain', score: 40 },
            { pattern: /@(temporary|temp|disposable|guerrilla|10minute)/i, description: 'Temporary email service', score: 35 },
            
            // Authority impersonation
            { pattern: /(paypal|amazon|microsoft|apple|google|facebook|twitter|instagram).*security/i, description: 'Impersonating major service security', score: 55 },
            { pattern: /(bank|irs|government|federal|tax|court|legal)/i, description: 'Government/authority impersonation', score: 50 },
            
            // Romance/relationship scams
            { pattern: /lonely|alone|widow|widower|military|deployed|overseas|soldier/i, description: 'Romance scam profile language', score: 30 },
            { pattern: /god.?fearing|honest|trustworthy|genuine|sincere.*person/i, description: 'Romance scam personality claims', score: 25 },
            
            // Investment scams
            { pattern: /investment opportunity|guaranteed return|profit margin|roi|passive income/i, description: 'Investment scam language', score: 40 },
            { pattern: /forex|binary options|crypto.?trading|mining.?investment/i, description: 'High-risk investment types', score: 45 },
            
            // Phishing attempts
            { pattern: /suspended.*account|expired.*session|re.?activate|re.?verify/i, description: 'Account suspension phishing', score: 45 },
            { pattern: /update.*payment.*method|billing.*information.*required/i, description: 'Payment information phishing', score: 50 },
            
            // Malware/virus warnings
            { pattern: /virus.*detected|malware.*found|computer.*infected|system.*compromised/i, description: 'Fake virus/malware warnings', score: 55 },
            
            // Fake delivery/shipping
            { pattern: /(ups|fedex|dhl|usps).*delivery.*failed|package.*waiting|shipment.*held/i, description: 'Fake shipping notifications', score: 40 }
        ];

        // === EXPANDED MESSAGE PATTERNS ===
        this.messagePatterns = [
            // Romance scam indicators
            { pattern: /love|heart|soul.?mate|marry|marriage|relationship|affection|care.*you/i, description: 'Romance scam emotional language', score: 30 },
            { pattern: /widow|widower|military|soldier|deployed|overseas|doctor|engineer.*abroad/i, description: 'Romance scam profession claims', score: 35 },
            { pattern: /god.?fearing|christian|honest|trustworthy|genuine.*person/i, description: 'Romance scam character claims', score: 25 },
            
            // Investment/financial scams
            { pattern: /investment|profit|return|guarantee|double.*money|roi|passive.*income/i, description: 'Investment scam language', score: 35 },
            { pattern: /forex|binary.*options|crypto.?trading|bitcoin.*investment|mining/i, description: 'High-risk investment schemes', score: 40 },
            { pattern: /financial.*freedom|make.*money.*home|work.*from.*home/i, description: 'Get-rich-quick schemes', score: 30 },
            
            // Tech support scams
            { pattern: /tech.*support|computer.*problem|virus|infected|microsoft.*calling|apple.*support/i, description: 'Tech support scam', score: 40 },
            { pattern: /remote.*access|teamviewer|anydesk|logmein|screen.*share/i, description: 'Remote access requests', score: 55 },
            { pattern: /windows.*license|software.*expired|antivirus.*expired/i, description: 'Fake software expiration', score: 45 },
            
            // Government impersonation
            { pattern: /social.*security|ssn|government|irs|tax.*refund|arrest.*warrant|court|legal.*action/i, description: 'Government authority impersonation', score: 50 },
            { pattern: /federal.*agency|homeland.*security|fbi|police.*department/i, description: 'Law enforcement impersonation', score: 55 },
            { pattern: /immigration|visa|deportation|citizenship/i, description: 'Immigration scam language', score: 40 },
            
            // Emergency/help scams
            { pattern: /emergency|hospital|accident|stranded|help.*me|urgent.*help|trouble/i, description: 'Emergency assistance scam tactics', score: 35 },
            { pattern: /medical.*emergency|surgery|treatment|medication.*money/i, description: 'Medical emergency scams', score: 40 },
            
            // Inheritance/advance fee scams
            { pattern: /inheritance|will|estate|beneficiary|deceased|attorney|lawyer|legal.*representative/i, description: 'Inheritance scam language', score: 40 },
            { pattern: /transfer.*money|move.*funds|processing.*fee|handling.*fee|tax.*payment/i, description: 'Advance fee fraud language', score: 45 },
            { pattern: /diplomatic.*bag|consignment|security.*company|courier.*service/i, description: 'Fake delivery/transfer methods', score: 50 },
            
            // Communication platform abuse
            { pattern: /(whatsapp|telegram|signal|viber|skype).*chat|move.*to.*(whatsapp|telegram)/i, description: 'Suspicious communication platform requests', score: 25 },
            { pattern: /google.*hangouts|gmail.*chat|yahoo.*messenger/i, description: 'Communication platform targeting', score: 20 },
            
            // Prize/lottery scams
            { pattern: /won.*lottery|lottery.*winner|jackpot|cash.*prize|sweepstakes/i, description: 'Lottery and prize scam claims', score: 45 },
            { pattern: /claim.*prize|collection.*agent|prize.*money|winning.*number/i, description: 'Prize claiming instructions', score: 40 },
            
            // Charity/disaster scams
            { pattern: /charity|donation|disaster.*relief|hurricane|earthquake|flood.*victims/i, description: 'Charity and disaster scam appeals', score: 35 },
            { pattern: /orphanage|children.*need|medical.*help.*children/i, description: 'Fake charity emotional appeals', score: 40 },
            
            // Job/employment scams
            { pattern: /job.*offer|employment.*opportunity|work.*from.*home|easy.*money/i, description: 'Job scam language', score: 25 },
            { pattern: /personal.*assistant|money.*transfer.*agent|payment.*processor/i, description: 'Money laundering job offers', score: 50 },
            
            // Rental/real estate scams
            { pattern: /apartment.*rent|house.*rent|property.*available|landlord/i, description: 'Rental scam language', score: 20 },
            { pattern: /security.*deposit|first.*month.*rent|key.*money|viewing.*fee/i, description: 'Rental advance fee requests', score: 35 },
            
            // Fake product/medication sales
            { pattern: /weight.*loss|male.*enhancement|miracle.*cure|no.*prescription|pharmacy/i, description: 'Fake medication/product sales', score: 40 },
            
            // Blackmail/extortion
            { pattern: /embarrassing.*video|intimate.*photos|webcam|blackmail|extortion|expose/i, description: 'Blackmail and sextortion', score: 60 },
            
            // Cryptocurrency scams
            { pattern: /bitcoin.*wallet|crypto.*investment|blockchain|nft.*opportunity|defi/i, description: 'Cryptocurrency scam language', score: 35 },
            { pattern: /mining.*contract|trading.*bot|guaranteed.*profit.*crypto/i, description: 'Crypto investment scams', score: 45 }
        ];

        // === EXPANDED LEGITIMATE PATTERNS (Reduce false positives) ===
        this.legitimatePatterns = [
            // Official government domains
            { pattern: /https:\/\/.*\.gov(\.[a-z]{2})?\//, description: 'Official government website', score: -30 },
            { pattern: /https:\/\/.*\.(edu|ac\.[a-z]{2})\//, description: 'Educational institution domain', score: -20 },
            
            // Legitimate organizations
            { pattern: /https:\/\/.*\.(org|ngo)\//, description: 'Non-profit organization domain', score: -15 },
            
            // Customer service language
            { pattern: /customer.*service|help.*center|support.*team|contact.*us|faq|frequently.*asked/i, description: 'Legitimate customer service language', score: -10 },
            
            // Legal/compliance elements
            { pattern: /privacy.*policy|terms.*of.*service|terms.*and.*conditions|unsubscribe|opt.?out/i, description: 'Legitimate legal/compliance elements', score: -15 },
            { pattern: /gdpr|ccpa|data.*protection|cookie.*policy/i, description: 'Privacy regulation compliance', score: -20 },
            
            // Legitimate business communication
            { pattern: /invoice|receipt|order.*confirmation|shipping.*notification|delivery.*update/i, description: 'Legitimate business communication', score: -10 },
            
            // Official branded domains (major services)
            { pattern: /https:\/\/(www\.)?(google|microsoft|apple|amazon|paypal|facebook|twitter|linkedin|github|stackoverflow)\.com/i, description: 'Legitimate major service domain', score: -25 },
            { pattern: /https:\/\/(mail|outlook|gmail|yahoo)\./, description: 'Legitimate email service', score: -15 },
            
            // Professional email signatures
            { pattern: /best.*regards|sincerely|kind.*regards|yours.*truly/i, description: 'Professional email closing', score: -5 },
            { pattern: /phone:.*[0-9]|tel:.*[0-9]|office:.*[0-9]/i, description: 'Contact information provided', score: -10 },
            
            // Legitimate financial terms
            { pattern: /bank.*statement|account.*balance|transaction.*history|monthly.*statement/i, description: 'Legitimate banking communication', score: -10 },
            
            // SSL/Security indicators (when mentioned appropriately)
            { pattern: /secure.*connection|ssl.*certificate|encrypted.*communication/i, description: 'Security awareness language', score: -5 }
        ];

        // Enhanced common words dictionary (expanded significantly)
        this.commonWords = new Set([
            // Basic common words
            'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i', 'it', 'for', 'not', 'on', 
            'with', 'he', 'as', 'you', 'do', 'at', 'this', 'but', 'his', 'by', 'from', 'they', 'we', 
            'say', 'her', 'she', 'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their',
            'what', 'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go', 'me', 'when',
            'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know', 'take', 'people', 'into',
            'year', 'your', 'good', 'some', 'could', 'them', 'see', 'other', 'than', 'then', 'now',
            'look', 'only', 'come', 'its', 'over', 'think', 'also', 'back', 'after', 'use', 'two',
            'how', 'our', 'work', 'first', 'well', 'way', 'even', 'new', 'want', 'because', 'any',
            'these', 'give', 'day', 'most', 'us', 'is', 'water', 'been', 'call', 'who', 'oil', 'sit',
            'now', 'find', 'long', 'down', 'day', 'did', 'get', 'has', 'him', 'had', 'let', 'put', 'say',
            'too', 'old', 'why', 'how', 'its', 'our', 'out', 'two', 'way', 'who', 'boy', 'did', 'man',
            'new', 'now', 'old', 'see', 'got', 'may', 'try', 'ask', 'end', 'big', 'far', 'sea', 'eye',
            
            // Extended vocabulary
            'email', 'message', 'website', 'internet', 'computer', 'phone', 'account', 'password', 'user',
            'service', 'customer', 'support', 'help', 'contact', 'information', 'please', 'thank', 'thanks',
            'hello', 'dear', 'regards', 'sincerely', 'best', 'kind', 'today', 'tomorrow', 'yesterday',
            'morning', 'afternoon', 'evening', 'night', 'week', 'month', 'year', 'business', 'company',
            'order', 'payment', 'money', 'price', 'cost', 'free', 'offer', 'sale', 'buy', 'sell',
            'product', 'item', 'delivery', 'shipping', 'send', 'receive', 'address', 'name', 'number',
            'date', 'time', 'welcome', 'congrats', 'sorry', 'excuse', 'problem', 'issue', 'question',
            'answer', 'reply', 'response', 'confirm', 'cancel', 'update', 'change', 'delete', 'remove'
        ]);

        // Suspicious file extensions (expanded)
        this.suspiciousExtensions = new Set([
            'exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'vbs', 'js', 'jar', 'wsf', 'wsh', 'ps1',
            'msi', 'hta', 'cpl', 'msc', 'reg', 'scf', 'lnk', 'inf', 'dll'
        ]);

        // Known scam domains and patterns (regularly updated list)
        this.knownScamDomains = new Set([
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link', 'is.gd',
            'buff.ly', 'rebrand.ly', 'cutt.ly', 'tiny.cc'
        ]);

        // Suspicious TLDs (expanded)
        this.suspiciousTlds = new Set([
            'tk', 'ml', 'ga', 'cf', 'xyz', 'click', 'download', 'bid', 'country', 'loan',
            'win', 'review', 'racing', 'accountant', 'faith', 'cricket', 'science', 'work',
            'party', 'gq', 'men', 'ren'
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
