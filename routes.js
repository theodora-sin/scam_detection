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
            { pattern: /%[0-9a-f]{2}{3,}/i, description: 'Excessive URL encoding (potential obfuscation)', score: 35 }
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

    // Rest of the methods remain the same but with enhanced pattern matching
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
                case 'phone':
                    return this._analyzePhone(content);
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
            
            // Additional URL-specific checks
            const domain = urlObj.hostname.toLowerCase();
            const path = urlObj.pathname.toLowerCase();
            
            // Check against known scam domains
            if (this.knownScamDomains.has(domain)) {
                riskScore += 35;
                detectedPatterns.push('Known URL shortening service');
            }
            
            // Check TLD
            const tld = domain.split('.').pop();
            if (this.suspiciousTlds.has(tld)) {
                riskScore += 25;
                detectedPatterns.push(`Suspicious top-level domain: .${tld}`);
            }
            
            // Check for suspicious file extensions in path
            const fileExtMatch = path.match(/\.([a-z0-9]+)(\?|$)/);
            if (fileExtMatch && this.suspiciousExtensions.has(fileExtMatch[1])) {
                riskScore += 60;
                detectedPatterns.push(`Suspicious file extension: .${fileExtMatch[1]}`);
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
        
        // Add domain age simulation and other advanced checks
        const advancedAnalysis = this._performAdvancedUrlAnalysis(url);
        riskScore += advancedAnalysis.score;
        detectedPatterns.push(...advancedAnalysis.factors);
        
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
        
        // Email-specific analysis
        const emailSpecific = this._performAdvancedEmailAnalysis(emailContent);
        riskScore += emailSpecific.score;
        detectedPatterns.push(...emailSpecific.factors);

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
        
        // Message-specific analysis
        const messageSpecific = this._performAdvancedMessageAnalysis(message);
        riskScore += messageSpecific.score;
        detectedPatterns.push(...messageSpecific.factors);
        
        return this._formatResult(riskScore, detectedPatterns, message, 'Message');
    }

    _analyzePhone(phoneNumber) {
        let riskScore = 0;
        const detectedPatterns = [];
        
        // Clean phone number
        const cleaned = phoneNumber.replace(/[^\d+]/g, '');
        
        // Common scam number patterns
        const phonePatterns = [
            { pattern: /^\+?1-?8(00|33|44|55|66|77|88|99)/, description: 'Common scam toll-free pattern', score: 35 },
            { pattern: /^\+?1-?[0-9]{3}-?000-?[0-9]{4}/, description: 'Suspicious number format', score: 30 },
            { pattern: /^\+?(234|233|229|225|237|254)/, description: 'High-risk country codes (West Africa)', score: 45 },
            { pattern: /^\+?(375|380|996|998)/, description: 'High-risk country codes (Eastern Europe/Central Asia)', score: 40 },
            { pattern: /^(\+?1)?(555|888|777|666|999)/, description: 'Suspicious area/exchange codes', score: 25 }
        ];
        
        phonePatterns.forEach(({ pattern, description, score }) => {
            if (pattern.test(cleaned)) {
                riskScore += score;
                detectedPatterns.push(description);
            }
        });
        
        return this._formatResult(riskScore, detectedPatterns, phoneNumber, 'Phone');
    }

    // Advanced analysis methods
    _performAdvancedUrlAnalysis(url) {
        let score = 0;
        const factors = [];
        
        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname;
            const path = urlObj.pathname;
            
            // Domain length analysis
            if (domain.length > 30) {
                score += 20;
                factors.push('Unusually long domain name');
            }
            
            // Subdomain count
            const parts = domain.split('.');
            if (parts.length > 4) {
                score += 25;
                factors.push('Excessive subdomains');
            }
            
            // Path analysis
            if (path.includes('..')) {
                score += 40;
                factors.push('Path traversal attempt');
            }
            
            // Query parameter analysis
            const params = urlObj.searchParams;
            if (params.toString().length > 200) {
                score += 15;
                factors.push('Unusually long query parameters');
            }
            
        } catch (e) {
            // Already handled in main URL analysis
        }
        
        return { score, factors };
    }

    _performAdvancedEmailAnalysis(content) {
        let score = 0;
        const factors = [];
        
        // Check for email structure
        const hasSubject = /subject:/i.test(content);
        const hasFrom = /from:/i.test(content);
        const hasTo = /to:/i.test(content);
        
        if (!hasSubject && !hasFrom && !hasTo) {
            score += 10;
            factors.push('Missing standard email headers');
        }
        
        // Check for HTML content indicators
        const hasHtml = /<[a-z][\s\S]*>/i.test(content);
        const hasInlineStyles = /style\s*=/i.test(content);
        
        if (hasHtml && hasInlineStyles) {
            score += 15;
            factors.push('Suspicious HTML formatting');
        }
        
        // Check for hidden text (common in spam)
        const hiddenTextPatterns = [
            /color:\s*(white|#fff|#ffffff)/i,
            /font-size:\s*0/i,
            /display:\s*none/i
        ];
        
        hiddenTextPatterns.forEach(pattern => {
            if (pattern.test(content)) {
                score += 25;
                factors.push('Hidden text detected');
            }
        });
        
        // Check for suspicious attachments mentioned
        if (/attachment|attached|file|document|invoice|receipt.*attached/i.test(content)) {
            score += 20;
            factors.push('Mentions attachments');
        }
        
        // Check for multiple URLs (link farming)
        const urlMatches = content.match(/https?:\/\/[^\s]+/g) || [];
        if (urlMatches.length > 5) {
            score += 30;
            factors.push(`Excessive links detected (${urlMatches.length} links)`);
        }
        
        // Check for suspicious email forwarding
        if (/fwd:|forwarded|forward.*this|share.*this.*email/i.test(content)) {
            score += 15;
            factors.push('Email forwarding encouraged');
        }
        
        return { score, factors };
    }

    _performAdvancedMessageAnalysis(content) {
        let score = 0;
        const factors = [];
        
        // Analyze message length vs content quality
        const wordCount = content.split(/\s+/).length;
        const sentenceCount = content.split(/[.!?]+/).length;
        
        if (wordCount > 200 && sentenceCount < 5) {
            score += 20;
            factors.push('Unusually long sentences (run-on text)');
        }
        
        // Check for copy-paste indicators
        const copyPastePatterns = [
            /copy.*paste|copy.*and.*paste/i,
            /forward.*this|share.*this.*message/i,
            /send.*to.*contacts|share.*with.*friends/i
        ];
        
        copyPastePatterns.forEach(pattern => {
            if (pattern.test(content)) {
                score += 25;
                factors.push('Encourages message forwarding');
            }
        });
        
        // Check for personal information requests
        const personalInfoPatterns = [
            /social.*security.*number|ssn/i,
            /date.*of.*birth|birthday/i,
            /mother.*maiden.*name/i,
            /bank.*account|routing.*number/i,
            /credit.*card|debit.*card/i,
            /pin.*number|password/i
        ];
        
        personalInfoPatterns.forEach(pattern => {
            if (pattern.test(content)) {
                score += 35;
                factors.push('Requests personal information');
            }
        });
        
        // Check for emotional manipulation
        const emotionalPatterns = [
            /please.*help|need.*your.*help|desperate/i,
            /dying|cancer|terminal|illness/i,
            /orphan|homeless|refugee/i,
            /god.*bless|prayers|blessed/i,
            /trust.*me|honest.*person/i
        ];
        
        emotionalPatterns.forEach(pattern => {
            if (pattern.test(content)) {
                score += 20;
                factors.push('Emotional manipulation tactics');
            }
        });
        
        // Check for urgency escalation
        if (/asap|a\.s\.a\.p|immediately|right.*now|urgent/i.test(content)) {
            score += 15;
            factors.push('Creates false urgency');
        }
        
        return { score, factors };
    }

    // Enhanced text quality analysis
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

        let score = 0;
        let factors = [];

        // Enhanced spelling/vocabulary check
        const uncommonWords = words.filter(word => !this.commonWords.has(word));
        const errorDensity = uncommonWords.length / words.length;
        
        if (errorDensity > 0.8) {
            score += 45;
            factors.push(`Very poor text quality (${uncommonWords.length} uncommon/misspelled words)`);
        } else if (errorDensity > 0.6) {
            score += 30;
            factors.push(`Poor text quality (${uncommonWords.length} uncommon words)`);
        } else if (errorDensity > 0.4) {
            score += 15;
            factors.push(`Below average text quality (${uncommonWords.length} uncommon words)`);
        }
        
        // Check for excessive capitalization
        const capsCount = (content.match(/[A-Z]/g) || []).length;
        const capsRatio = capsCount / content.length;
        if (capsRatio > 0.4 && content.length > 20) {
            score += 25;
            factors.push('Excessive capitalization (shouting)');
        } else if (capsRatio > 0.2 && content.length > 50) {
            score += 15;
            factors.push('High capitalization ratio');
        }
        
        // Check for number/letter substitution (l33t speak abuse)
        const leetPatterns = [
            /[0-9]{3,}/, // Excessive numbers
            /[a-z][0-9][a-z]|[0-9][a-z][0-9]/, // Number-letter mixing
            /@|\$|3|1|0/g // Common substitutions
        ];
        
        leetPatterns.forEach((pattern, index) => {
            if (pattern.test(content)) {
                score += index === 0 ? 10 : 15;
                factors.push('Suspicious character substitutions');
            }
        });
        
        // Check for repetitive patterns
        const repetitivePatterns = [
            /(.)\1{4,}/, // Same character 5+ times
            /(\w+)\s+\1\s+\1/, // Same word repeated 3+ times
            /!{3,}|\?{3,}|\.{4,}/ // Excessive punctuation
        ];
        
        repetitivePatterns.forEach(pattern => {
            if (pattern.test(content)) {
                score += 20;
                factors.push('Repetitive or excessive patterns');
            }
        });
        
        // Check for mixed languages (suspicious in context)
        const languagePatterns = [
            /[а-я]{3,}/i, // Cyrillic
            /[α-ω]{3,}/i, // Greek
            /[א-ת]{3,}/i, // Hebrew
            /[ا-ي]{3,}/i  // Arabic
        ];
        
        const languageCount = languagePatterns.filter(pattern => pattern.test(content)).length;
        if (languageCount > 0 && /[a-z]{10,}/i.test(content)) {
            score += 25;
            factors.push('Mixed languages detected');
        }
        
        return { score, factors };
    }

    // Enhanced character set analysis
    _analyzeCharacterSets(content) {
        if (!content) return { score: 0, factors: [] };

        // Check for mixed character sets (homograph attacks)
        const characterSets = {
            latin: /[a-zA-Z]/.test(content),
            cyrillic: /[\u0400-\u04FF]/.test(content),
            greek: /[\u0370-\u03FF]/.test(content),
            arabic: /[\u0600-\u06FF]/.test(content),
            hebrew: /[\u0590-\u05FF]/.test(content),
            chinese: /[\u4E00-\u9FFF]/.test(content),
            japanese: /[\u3040-\u309F\u30A0-\u30FF]/.test(content)
        };

        const activeSets = Object.keys(characterSets).filter(set => characterSets[set]);
        
        if (activeSets.length > 1) {
            let score = 30 + (activeSets.length - 2) * 15;
            return {
                score: Math.min(score, 60),
                factors: [`Mixed character sets detected: ${activeSets.join(', ')} (potential homograph attack)`]
            };
        }
        
        // Check for suspicious Unicode characters
        const suspiciousUnicode = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064]/;
        if (suspiciousUnicode.test(content)) {
            return {
                score: 40,
                factors: ['Hidden Unicode characters detected']
            };
        }
        
        return { score: 0, factors: [] };
    }

    // Enhanced pattern checking with context awareness
    _checkPatterns(content, patterns, detectedPatterns) {
        let score = 0;
        const contentLower = content.toLowerCase();
        
        for (const { pattern, description, score: patternScore } of patterns) {
            const matches = content.match(pattern) || [];
            if (matches.length > 0) {
                // Apply score multiplier for multiple matches
                let multiplier = 1;
                if (matches.length > 1) {
                    multiplier = 1 + (matches.length - 1) * 0.3;
                }
                
                const adjustedScore = Math.ceil(patternScore * multiplier);
                score += adjustedScore;
                
                if (patternScore > 0) {
                    const matchDescription = matches.length > 1 ? 
                        `${description} (${matches.length} instances)` : description;
                    detectedPatterns.push(matchDescription);
                }
            }
        }
        return score;
    }

    _formatResult(riskScore, detectedPatterns, content, contentType) {
        const finalScore = Math.max(0, Math.min(100, riskScore));
        const level = this._calculateRiskLevel(finalScore);
        
        return {
            level,
            score: finalScore,
            factors: detectedPatterns,
            details: this._generateAnalysisDetails(contentType, content, finalScore, detectedPatterns),
            recommendations: this._generateRecommendations(level, contentType, detectedPatterns),
            timestamp: new Date().toISOString()
        };
    }

    _calculateRiskLevel(riskScore) {
        if (riskScore >= 70) return 'high';
        if (riskScore >= 40) return 'medium';
        return 'low';
    }

    _generateRecommendations(level, contentType, patterns) {
        const recommendations = [];
        
        switch (level) {
            case 'high':
                recommendations.push('🚨 HIGH RISK: Do not interact with this content');
                recommendations.push('❌ Do not click any links or provide information');
                recommendations.push('🚫 Block sender and report as spam/scam');
                recommendations.push('📞 Report to authorities if threats are involved');
                break;
                
            case 'medium':
                recommendations.push('⚠️ MEDIUM RISK: Exercise extreme caution');
                recommendations.push('🔍 Verify sender through official channels');
                recommendations.push('👥 Consult with trusted person before responding');
                recommendations.push('🛡️ Do not provide personal or financial information');
                break;
                
            case 'low':
                recommendations.push('✅ LOW RISK: Content appears relatively safe');
                recommendations.push('🔒 Still maintain standard security practices');
                recommendations.push('📧 Only respond if you initiated the contact');
                recommendations.push('🤔 When in doubt, verify independently');
                break;
        }
        
        // Context-specific recommendations
        if (contentType === 'url') {
            recommendations.push('🌐 Hover over links to see actual destination');
            recommendations.push('🔐 Check for HTTPS and valid certificates');
        }
        
        if (patterns.some(p => p.toLowerCase().includes('payment'))) {
            recommendations.push('💳 Legitimate services don\'t request payment via gift cards');
            recommendations.push('🏦 Contact your bank if you\'ve shared financial info');
        }
        
        if (patterns.some(p => p.toLowerCase().includes('urgent'))) {
            recommendations.push('⏰ Real urgent matters rarely come via unsolicited messages');
            recommendations.push('📞 Call the organization directly using official numbers');
        }
        
        return recommendations;
    }

    _generateAnalysisDetails(contentType, content, riskScore, patterns) {
        let details = `=== ${contentType.toUpperCase()} ANALYSIS REPORT ===\n\n`;
        details += `Risk Assessment: ${this._calculateRiskLevel(riskScore).toUpperCase()}\n`;
        details += `Risk Score: ${riskScore}/100\n`;
        details += `Analysis Date: ${new Date().toLocaleString()}\n\n`;
        
        if (patterns.length > 0) {
            details += `RISK INDICATORS DETECTED (${patterns.length}):\n`;
            patterns.forEach((pattern, index) => {
                details += `${index + 1}. ${pattern}\n`;
            });
            details += '\n';
        } else {
            details += "✅ No specific risk indicators detected.\n\n";
        }
        
        details += "RECOMMENDATIONS:\n";
        const recommendations = this._generateRecommendations(this._calculateRiskLevel(riskScore), contentType, patterns);
        recommendations.forEach((rec, index) => {
            details += `${index + 1}. ${rec}\n`;
        });
        
        details += "\nADDITIONAL CONTEXT:\n";
        if (riskScore >= 70) {
            details += "• This content shows strong indicators of being a scam or malicious\n";
            details += "• Multiple suspicious patterns detected\n";
            details += "• Immediate caution advised - do not engage\n";
        } else if (riskScore >= 40) {
            details += "• This content shows several concerning indicators\n";
            details += "• Verification strongly recommended before taking any action\n";
            details += "• Could be legitimate but exercise caution\n";
        } else {
            details += "• This content appears to have minimal risk indicators\n";
            details += "• Standard security practices still apply\n";
            details += "• When in doubt, verify through official channels\n";
        }
        
        return details;
    }
}

// Analysis History Storage (unchanged)
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
            
            this._memoryStorage = history;
            this._saveToStorage(history);
            
            return analysis;
        } catch (error) {
            console.error('Error adding analysis to history:', error);
            return null;
        }
    }

    getHistory() {
        try {
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
            return true;
        }
    }

    _saveToStorage(history) {
        try {
            localStorage.setItem(this.storageKey, JSON.stringify(history));
        } catch (error) {
            console.warn('Could not save to localStorage, using memory storage only');
        }
    }

    getStatistics() {
        const history = this.getHistory();
        if (history.length === 0) return null;

        return {
            total: history.length,
            high_risk: history.filter(h => h.risk_level === 'high').length,
            medium_risk: history.filter(h => h.risk_level === 'medium').length,
            low_risk: history.filter(h => h.risk_level === 'low').length,
            avg_score: Math.round(history.reduce((sum, h) => sum + h.risk_score, 0) / history.length),
            content_types: {
                url: history.filter(h => h.content_type === 'url').length,
                email: history.filter(h => h.content_type === 'email').length,
                message: history.filter(h => h.content_type === 'message').length,
                phone: history.filter(h => h.content_type === 'phone').length
            }
        };
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ScamAnalyzer, AnalysisHistory };
} else if (typeof window !== 'undefined') {
    window.ScamAnalyzer = ScamAnalyzer;
    window.AnalysisHistory = AnalysisHistory;
}
