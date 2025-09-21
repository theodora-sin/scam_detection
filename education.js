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
        // Search functionality
        const searchInput = document.getElementById('scam-search');
        if (searchInput) {
            let searchTimeout;
            searchInput.addEventListener('input', () => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.searchScamTypes(searchInput.value);
                }, 300);
            });
        }
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
        this.searchScamTypes('');
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
            </div>
        `).join('');
    }

    loadReportingResources() {
        const resourcesContainer = document.getElementById('reporting-resources');
        if (!resourcesContainer) return;

        // Add warning section based on your original content
        const warningSection = `
            <div class="warning-card" style="background: #f8d7da; border-color: #dc3545; color: #721c24; margin-bottom: 2rem;">
                <h4>⚠️ If you suspect this website is a scam:</h4>
                <ul style="margin: 1rem 0; padding-left: 2rem;">
                    <li>Do NOT click the link</li>
                    <li>Find someone you trust</li>
                    <li>Report to the appropriate authorities</li>
                </ul>
            </div>
        `;

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
                name:"Phishing Email",
                category: "Identity Theft",
                description: "Fraudulent emails designed to steal personal information by impersonating legitimate organizations.",
                warning_signs: "Urgent language, suspicious sender addresses, requests for personal information, poor grammar/spelling, generic greetings",
                prevention_tips: "Always verify sender authenticity, check URLs carefully, never provide sensitive information via email, use official websites directly",
                severity: "high",
            },
            {
                name:"Tech Support Scam",
                category: "Service Fraud",
                description: "Scammers pose as technical support to gain remote access to computers or steal money.",
                warning_signs: "Unsolicited calls about computer problems, requests for remote access, pressure to act immediately, requests for payment",
                prevention_tips: "Never give remote access to unsolicited callers, verify identity independently, hang up and call official support",
                severity: "high",
            },
            {
                name:"Romance Scam",
                category: "Relationship Fraud",
                description: "Criminals create fake romantic relationships online to manipulate victims into sending money.",
                warning_signs: "Professes love quickly, avoids meeting in person, has emergencies requiring money, limited photos, stories don't add up",
                prevention_tips: "Be cautious of online relationships, never send money to someone you haven't met, verify identity through video calls",
                severity: "medium",
            },
            {
                name:"Investment/Cryptocurrency Scam",
                category: "Financial Fraud",
                description: "Fraudulent investment opportunities promising unrealistic returns, often involving cryptocurrency.",
                warning_signs: "Guaranteed high returns, pressure to invest quickly, unlicensed sellers, complex fee structures, celebrity endorsements",
                prevention_tips: "Research investments thoroughly, verify licenses, be skeptical of guaranteed returns, check regulatory warnings",
                severity: "high",
            },
            {
                name:"Online Shopping Scam",
                category: "E-commerce Fraud",
                description: "Fake online stores that take payment but never deliver goods, or sell counterfeit items.",
                warning_signs: "Prices too good to be true, no contact information, poor website design, no customer reviews, payment only by wire transfer",
                prevention_tips: "Shop from reputable retailers, check reviews and ratings, use secure payment methods with buyer protection",
                severity: "medium",
            },
            {
                name:"Social Security Scam",
                category: "Government Impersonation",
                description: "Criminals impersonate Social Security Administration officials to steal personal information or money.",
                warning_signs: "Threats of arrest or legal action, demands for immediate payment, requests for Social Security number verification",
                prevention_tips: "SSA will never call you demanding immediate payment, verify independently by calling official SSA number, never give SSN over phone",
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
