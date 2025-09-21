// Education Screen Controller
class EducationScreen {
    constructor(app) {
        this.app = app;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadEducationContent();
    }

    setupEventListeners() {
        // No search bar, so nothing to set up
    }

    loadEducationContent() {
        this.loadProtectionTips();
        this.loadRedFlags();
        this.loadScamTypes();
        this.loadReportingResources();
    }

    loadProtectionTips() {
        const tipsContainer = document.getElementById('protection-tips');
        if (!tipsContainer) return;

        // Based on your original practical tips
        const tips = [
            "Never share personal information via email or phone",
            "Verify URLs before clicking suspicious links", 
            "Be skeptical of urgent or time-pressured requests",
            "Be careful about replying to contact numbers or emails",
            "Be cautious of unusual payment methods",
            "Discuss suspicious messages with a trusted person",
            "Never share bank details, names, or financial information on social platforms",
            "Keep software and browsers updated",
            "Use strong, unique passwords with Two Factor Authentication"
        ];

        tipsContainer.innerHTML = tips.map(tip => 
            `<div class="tip-card">✅ ${tip}</div>`
        ).join('');
    }

    loadRedFlags() {
        const redFlagsContainer = document.getElementById('red-flags');
        if (!redFlagsContainer) return;

        // Based on your original focused red flags
        const redFlags = [
            "Look for suspicious keywords",
            "Requests for immediate payment", 
            "Payments via gift cards or cryptocurrency (e.g., Bitcoin)",
            "Poor grammar, spelling, or punctuation in messages",
            "Unsolicited contact about problems or prizes",
            "Pressure to keep communication secret",
            "Requests for remote computer access",
            "Too-good-to-be-true offers or guarantees",
            "Urgent threats about account suspension or legal action"
        ];

        redFlagsContainer.innerHTML = redFlags.map(flag => 
            `<div class="warning-card">🚩 ${flag}</div>`
        ).join('');
    }

    loadScamTypes() {
        this.renderAllScamTypes();
    }

    renderAllScamTypes() {
        // This function should render all scam types without filtering
        const scamTypesList = document.getElementById('scam-types-list');
        if (!scamTypesList) return;
        const scamTypes = this.getScamTypesData();
        scamTypesList.innerHTML = scamTypes.map(type =>
            `<div class="scam-type-card"><h4>${type.name}</h4><p>${type.category}</p><p>${type.warning_signs}</p><p>${type.prevention_tips}</p><p>Severity: ${type.severity.toUpperCase()}</p><p>${type.description}</p><h5>⚠️ Warning Signs:</h5><p>${type.warning_signs}</p><h5>💡 Prevention Tips:</h5><p>${type.prevention_tips}</p><div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid #dee2e6;"><small><strong>Severity:</strong> ${type.severity.toUpperCase()}</small></div><p><strong>Description:</strong> ${type.description}</p></div>`
        ).join('');
    }

    searchScamTypes(query) {
        const resultsContainer = document.getElementById('scam-types-list');
        if (!resultsContainer) return;

        const scamTypes = this.getScamTypesData();
        const filteredTypes = query.trim() === '' ? scamTypes : 
            scamTypes.filter(scam => 
                scam.name.toLowerCase().includes(query.toLowerCase()) ||
                scam.description.toLowerCase().includes(query.toLowerCase()) ||
                scam.category.toLowerCase().includes(query.toLowerCase())
            );

        if (filteredTypes.length === 0) {
            resultsContainer.innerHTML = '<p>No scam types found matching your search.</p>';
            return;
        }

        resultsContainer.innerHTML = filteredTypes.map(scam => `
            <div class="scam-type-card">
                <h4>${scam.name}</h4>
                <p><strong>Category:</strong> ${scam.category}</p>
                <p><strong>Description:</strong> ${scam.description}</p>
                
                <h5>⚠️ Warning Signs:</h5>
                <p>${scam.warning_signs}</p>
                
                <h5>💡 Prevention Tips:</h5>
                <p>${scam.prevention_tips}</p>
                
                <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid #dee2e6;">
                    <small><strong>Severity:</strong> ${scam.severity.toUpperCase()}</small>
            </div>
        `).join('');
    }

    loadReportingResources() {
        const resourcesContainer = document.getElementById('reporting-resources');
        if (!resourcesContainer) return;

        // Add warning section based on your original content
        const warningSection = `
            <div class="warning-card" style="background: #f8d7da; border-color: #dc3545; color: #721c24; margin-bottom: 2rem;">
                <h4>⚠️ If you suspect the website is a scam:</h4>
                <ul style="margin: 1rem 0; padding-left: 2rem;">
                    <li>Do NOT click the link</li>
                    <li>Find someone you trust</li>
                    <li>Report to the appropriate authorities</li>
                </ul>
            </div>
        `;

        const resources = [
            {
                name: "FTC Fraud Reports",
                url: "https://reportfraud.ftc.gov/",
                description: "Report fraud to the Federal Trade Commission (USS only)"
            },
            {
                name: "FBI IC3",
                url: "https://www.ic3.gov/",
                description: "Internet Crime Complaint Center"
            },
            {
                name: "UK Scam Reports",
                url: "https://www.ncsc.gov.uk/collection/phishing-scams",
                description: "Spot and report scam emails, texts, websites and calls(UK only)"
            },
            {
                name: "AARP Fraud Watch",
                url: "https://www.aarp.org/money/scams-fraud/",
                description: "Resources and support for fraud victims"
            },
            {
                name: "Australia Scam Reports",
                url: "https://www.scamwatch.gov.au/report-a-scam",
                description: "Report scam emails (Australia only)"
            }            
        ];

        resourcesContainer.innerHTML = warningSection + resources.map(resource => `
            <div class="card">
                <h4><a href="${resource.url}" target="_blank" rel="noopener noreferrer">${resource.name} 🔗</a></h4>
                <p>${resource.description}</p>
            </div>
        `).join('');
    }

    getScamTypesData() {
        return [
            {
                name: "Phishing Email",
                category: "Identity Theft",
                description: "Fraudulent emails designed to steal personal information by impersonating legitimate organizations.",
                warning_signs: "Urgent language, suspicious sender addresses, requests for personal information, poor grammar/spelling, generic greetings",
                prevention_tips: "Always verify sender authenticity, check URLs carefully, never provide sensitive information via email, use official websites directly",
                severity: "high",
            },
            {
                name: "Account/Password Reset Scam",
                category: "Phishing",
                description: "Messages pretending to be from legitimate or popular services, claiming your account is compromised and urging you to reset your password via a provided link.",
                warning_signs: "Unexpected password reset emails, links to fake websites, requests for personal information",
                prevention_tips: "never click on links in unsolicited resest emails, go directly to the official website to reset passwords, enable two-factor authentication",
                severity: "high",
            },                        
            {
                name: "Tech Support Scam",
                category: "Service Fraud",
                description: "Scammers pose as technical support to gain remote access to computers or steal money.",
                warning_signs: "Unsolicited calls about computer problems, requests for remote access, pressure to act immediately, requests for payment",
                prevention_tips: "Never give remote access to unsolicited callers, verify identity independently, hang up and call official support",
                severity: "high",
            },
            {
                name: "Romance Scam",
                category: "Relationship Fraud",
                description: "Criminals create fake romantic relationships online to manipulate victims into sending money.",
                warning_signs: "Professes love quickly, avoids meeting in person, has emergencies requiring money, limited photos, stories don't add up",
                prevention_tips: "Be cautious of online relationships, never send money to someone you haven't met, verify identity through video calls",
                severity: "medium",
            },
            {
                name:"Charity/Disaster Scam",
                category: "Financial Fraud",
                description: "Fake charities or disaster relief efforts soliciting donations that go to scammers instead of victims.",
                warning_signs: "Pressure to donate immediately, no proof of legitimacy, vague or generic charity names",
                prevention_tips: "Research charities on official registries, donate through trusted organizations, never give in to urgent pressure",
                severity: "medium",
            },
            {
                name: "Police/Tax Authority Scam",
                category: "Government Impersonation",
                description: "Scammers impersonate police or tax authorities, threatening arrest or legal action to extort money.",
                warning_signs: "Unsolicited calls or messages, threats of arrest, demands for immediate payment, requests for personal information",
                prevention_tips: "Government agencies don’t demand payments over the phone, hang up and verify independently",
                severity: "high",
            },
            {
                name: "Investment/Cryptocurrency Scam",
                category: "Financial Fraud",
                description: "Fraudulent investment opportunities promising unrealistic returns, often involving cryptocurrency.",
                warning_signs: "Guaranteed high returns, pressure to invest quickly, unlicensed sellers, complex fee structures, celebrity endorsements",
                prevention_tips: "Research investments thoroughly, verify licenses, be skeptical of guaranteed returns, check regulatory warnings",
                severity: "high",
            },
            {
                name: "Lottery/Prize Scam",
                category: "Financial Fraud",
                description: "Notifications claiming you've won a lottery or prize, requiring payment of fees or taxes to claim.",
                warning_signs: "Unexpected prize notifications, requests for upfront fees or taxes, pressure to act quickly, no proof of winning",
                prevention_tips: "Legitimate lotteries don’t ask for fees, verify through official sources, never send money to claim prizes",
                severity: "high",
            },
            {
                name: "Credit Cardd/Payment Scam",
                category: "Financial Fraud",
                description: "Fraudulent messages claiming issues with your credit card or payment method, urging you to verify details via a link.",
                warning_signs: "Unexpected payment issues, links to fake websites, requests for card details or personal information",
                prevention_tips: "Use secure payment platforms, never share card details over email or phone, check for HTTPS",
                severity: "high",
            },
            {
                name: "Online Shopping Scam",
                category: "E-commerce Fraud",
                description: "Fake online stores that take payment but never deliver goods, or sell counterfeit items.",
                warning_signs: "Prices too good to be true, no contact information, poor website design, no customer reviews, payment only by wire transfer",
                prevention_tips: "Shop from reputable retailers, check reviews and ratings, use secure payment methods with buyer protection",
                severity: "medium",
            },
            {
                name: "Delivery/Parcel Scam",
                category: "Consumer Fraud",
                description: "Fake delivery notifications claimng a package is undeliverable or requires payment to release.",
                warning_signs: "Unexpected delivery notifications, requests for payment or personal information to release a package, links to fake courier websites",
                prevention_tips: "Check with official courier services directly, don’t click on suspicious links, never pay fees for unknown packages",
                severity: "medium",
            },
            {
                name: "Rental/Real Estate Scam",
                category: "Property Fraud",
                description: "Fake rental listings or real estate offers designed to steal deposits or personal information.",
                warning_signs:"Pressure to send money before viewing, below-market prices, landlords unavailable to meet",
                prevention_tips: "Always view properties in person, verify landlord identity, use reputable rental platforms, never send money upfront",
                severity: "medium",
            },            
            {
                name: "Social Security Scam",
                category: "Government Impersonation",
                description: "Criminals impersonate Social Security Administration officials to steal personal information or money.",
                warning_signs: "Threats of arrest or legal action, demands for immediate payment, requests for Social Security number verification",
                prevention_tips: "SSA will never call you demanding immediate payment, verify independently by calling official SSA number, never give SSN over phone",
                severity: "high",
            },
            {
                name: "Police/Tax Authortiy Scam",
                category: "Government Impersonation",
                description: "Scammers impersonate police or tax authorities, threatening arrest or legal action to extort money.",
                warning_signs: "Unsolicited calls or messages, threats of arrest, demands for immediate payment, requests for personal information",
                prevention_tips: "Government agencies don’t demand payments over the phone, hang up and verify independently",
                severity: "high",
            }

        ];
    }

    activate() {
        // Called when education screen becomes active
        console.log('Education screen activated');
        this.loadEducationContent();
    }

    deactivate() {
        // Called when education screen becomes inactive
        console.log('Education screen deactivated');
    }
}
