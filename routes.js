 // Scam Analysis Engine - JavaScript Implementation
class ScamAnalyzer {
    constructor() {
        // Define scam patterns for different content types
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
        
        // Legitimate indicators (reduce risk score)
        this.legitimatePatterns = [
            { pattern: /https:\/\/.*\.gov\//i, description: 'Government website', score: -20 },
            { pattern: /https:\/\/.*\.(edu|org)\//i, description: 'Educational/non-profit domain', score: -10 },
            { pattern: /contact us|customer service|help center/i, description: 'Customer service language', score: -5 },
            { pattern: /privacy policy|terms of service|unsubscribe/i, description: 'Legitimate website elements', score: -10 }
        ];
    }

    analyzeContent(content, contentType) {
        try {
            if (contentType === 'url') {
                return this._analyzeUrl(content);
            } else if (contentType === 'email') {
                return this._analyzeEmail(content);
            } else if (contentType === 'message') {
                return this._analyzeMessage(content);
            } else {
                throw new Error(`Unsupported content type: ${contentType}`);
            }
        } catch (error) {
            console.error('Analysis error:', error);
            return {
                risk_level: 'unknown',
                risk_score: 0,
                detected_patterns: [],
                analysis_details: `Error during analysis: ${error.message}`
            };
        }
    }

    _analyzeUrl(url) {
        let riskScore = 0;
        let detectedPatterns = [];
        
        // Validate URL format
        try {
            new URL(url);
        } catch (error) {
            return {
                risk_level: 'high',
                risk_score: 100,
                detected_patterns: ['Invalid URL format'],
                analysis_details: 'The provided URL is not properly formatted.'
            };
        }
        
        // Check URL patterns
        for (const { pattern, description, score } of this.urlPatterns) {
            if (pattern.test(url)) {
                riskScore += score;
                detectedPatterns.push(description);
            }
        }
        
        // Check for legitimate patterns
        for (const { pattern, description, score } of this.legitimatePatterns) {
            if (pattern.test(url)) {
                riskScore += score; // score is negative for legitimate patterns
            }
        }
        
        const riskLevel = this._calculateRiskLevel(riskScore);
        const analysisDetails = this._generateUrlAnalysisDetails(url, riskScore, detectedPatterns);
        
        return {
            risk_level: riskLevel,
            risk_score: Math.max(0, riskScore),
            detected_patterns: detectedPatterns,
            analysis_details: analysisDetails
        };
    }

    _analyzeEmail(emailContent) {
        let riskScore = 0;
        let detectedPatterns = [];
        
        // Check email patterns
        for (const { pattern, description, score } of this.emailPatterns) {
            if (pattern.test(emailContent)) {
                riskScore += score;
                detectedPatterns.push(description);
            }
        }
        
        // Check for legitimate patterns
        for (const { pattern, description, score } of this.legitimatePatterns) {
            if (pattern.test(emailContent)) {
                riskScore += score;
            }
        }
        
        const riskLevel = this._calculateRiskLevel(riskScore);
        const analysisDetails = this._generateEmailAnalysisDetails(emailContent, riskScore, detectedPatterns);
        
        return {
            risk_level: riskLevel,
            risk_score: Math.max(0, riskScore),
            detected_patterns: detectedPatterns,
            analysis_details: analysisDetails
        };
    }

    _analyzeMessage(message) {
        let riskScore = 0;
        let detectedPatterns = [];
        
        // Check message patterns
        for (const { pattern, description, score } of this.messagePatterns) {
            if (pattern.test(message)) {
                riskScore += score;
                detectedPatterns.push(description);
            }
        }
        
        // Check for legitimate patterns
        for (const { pattern, description, score } of this.legitimatePatterns) {
            if (pattern.test(message)) {
                riskScore += score;
            }
        }
        
        const riskLevel = this._calculateRiskLevel(riskScore);
        const analysisDetails = this._generateMessageAnalysisDetails(message, riskScore, detectedPatterns);
        
        return {
            risk_level: riskLevel,
            risk_score: Math.max(0, riskScore),
            detected_patterns: detectedPatterns,
            analysis_details: analysisDetails
        };
    }

    _calculateRiskLevel(riskScore) {
        if (riskScore >= 60) {
            return 'high';
        } else if (riskScore >= 30) {
            return 'medium';
        } else {
            return 'low';
        }
    }

    _generateUrlAnalysisDetails(url, riskScore, patterns) {
        let details = `URL Analysis for: ${url}\n\n`;
        details += `Risk Score: ${Math.max(0, riskScore)}/100\n\n`;
        
        if (patterns.length > 0) {
            details += "Detected Risk Indicators:\n";
            for (const pattern of patterns) {
                details += `• ${pattern}\n`;
            }
        } else {
            details += "No specific risk indicators detected in the URL structure.\n";
        }
        
        details += "\nRecommendations:\n";
        if (riskScore >= 60) {
            details += "• Do not visit this URL\n• This appears to be a high-risk website\n• Report this URL if received unsolicited";
        } else if (riskScore >= 30) {
            details += "• Exercise caution before visiting\n• Verify the source of this URL\n• Don't enter personal information";
        } else {
            details += "• URL appears to be relatively safe\n• Still exercise normal web safety practices\n• Verify site authenticity if conducting transactions";
        }
        
        return details;
    }

    _generateEmailAnalysisDetails(email, riskScore, patterns) {
        let details = `Email Content Analysis\n\n`;
        details += `Risk Score: ${Math.max(0, riskScore)}/100\n\n`;
        
        if (patterns.length > 0) {
            details += "Detected Risk Indicators:\n";
            for (const pattern of patterns) {
                details += `• ${pattern}\n`;
            }
        } else {
            details += "No specific risk indicators detected in the email content.\n";
        }
        
        details += "\nRecommendations:\n";
        if (riskScore >= 60) {
            details += "• Do not respond to this email\n• Do not click any links\n• Mark as spam/phishing\n• Report to your email provider";
        } else if (riskScore >= 30) {
            details += "• Verify sender through alternative means\n• Be cautious of any requests for information\n• Don't click suspicious links";
        } else {
            details += "• Email appears relatively safe\n• Still verify sender identity for important requests\n• Exercise normal email safety practices";
        }
        
        return details;
    }

    _generateMessageAnalysisDetails(message, riskScore, patterns) {
        let details = `Message Content Analysis\n\n`;
        details += `Risk Score: ${Math.max(0, riskScore)}/100\n\n`;
        
        if (patterns.length > 0) {
            details += "Detected Risk Indicators:\n";
            for (const pattern of patterns) {
                details += `• ${pattern}\n`;
            }
        } else {
            details += "No specific risk indicators detected in the message content.\n";
        }
        
        details += "\nRecommendations:\n";
        if (riskScore >= 60) {
            details += "• Do not respond to this message\n• Do not send money or personal information\n• Block the sender\n• Report as suspected scam";
        } else if (riskScore >= 30) {
            details += "• Verify the sender's identity through other means\n• Be suspicious of any requests for money or information\n• Don't provide personal details";
        } else {
            details += "• Message appears relatively safe\n• Still be cautious with unsolicited communications\n• Verify identity for any important requests";
        }
        
        return details;
    }
}

// Export for use in other files
window.ScamAnalyzer = ScamAnalyzer;
