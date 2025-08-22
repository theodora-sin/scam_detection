// === Global Constants === //
const SCAM_PHRASES = [
  "urgent action required", "act now or lose forever", "limited time offer", "expires today",
  "immediate response required", "time sensitive", "claim your prize", "congratulations! you have won",
  "you've been selected", "lottery winner", "cash prize", "free gift", "free money",
  "confirm your personal information", "verify your account", "update your details",
  "confirm your identity", "security verification required", "account suspended",
  "wire transfer", "send money", "pay processing fee", "tax refund", "inheritance money",
  "investment opportunity", "hsbc", "hm office", "google verification", "paypal security",
  "amazon security", "microsoft support", "apple support", "irs notice", "click to unlock",
  "download now", "install software", "run this file", "enable macros", "don't tell anyone",
  "confidential matter", "help me transfer money", "i am dying", "refugee", "widow"
];

const SUSPICIOUS_DOMAINS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "secure-bank", "paypal-secure",
  "amazon-security", "microsoft-support", "apple-security", "google-verify", "facebook-security",
  "tk", "xyz"
];

const LEGITIMATE_DOMAINS = [
  "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
  "facebook.com", "twitter.com", "linkedin.com", "github.com", "stackoverflow.com",
  "wikipedia.org", "reddit.com", "youtube.com", "gmail.com", "outlook.com"
];

// === Scam Types Database === //
const SCAM_TYPES = [
  {
    id: 1,
    name: 'Phishing Email',
    description: 'Fraudulent emails designed to steal personal information by impersonating legitimate organizations.',
    warning_signs: 'Urgent language, suspicious sender addresses, requests for personal information, poor grammar/spelling, generic greetings',
    example: 'Email claiming your account will be closed unless you click a link and verify your credentials.',
    prevention_tips: 'Always verify sender authenticity, check URLs carefully, never provide sensitive information via email, use official websites directly',
    created_at: new Date('2024-01-15')
  },
  {
    id: 2,
    name: 'Tech Support Scam',
    description: 'Scammers pose as technical support to gain remote access to computers or steal money.',
    warning_signs: 'Unsolicited calls about computer problems, requests for remote access, pressure to act immediately, requests for payment',
    example: 'Cold call claiming your computer is infected and needs immediate fixing for a fee.',
    prevention_tips: 'Never give remote access to unsolicited callers, verify identity independently',
    created_at: new Date('2024-01-20')
  },
  {
    id: 3,
    name: 'Romance Scam',
    description: 'Criminals create fake romantic relationships online to manipulate victims into sending money.',
    warning_signs: 'Professes love quickly, avoids meeting in person, has emergencies requiring money, limited photos, stories don\'t add up',
    example: 'Online romantic interest who needs money for a family emergency or travel expenses to meet you.',
    prevention_tips: 'Be cautious of online relationships, never send money to someone you haven\'t met',
    created_at: new Date('2024-01-25')
  },
  {
    id: 4,
    name: 'Investment/Cryptocurrency Scam',
    description: 'Fraudulent investment opportunities promising unrealistic returns, often involving cryptocurrency.',
    warning_signs: 'Guaranteed high returns, pressure to invest quickly, unlicensed sellers, complex fee structures, celebrity endorsements',
    example: 'Social media ad promising to double your cryptocurrency investment in 30 days.',
    prevention_tips: 'Research investments thoroughly, verify licenses, be skeptical of guaranteed returns',
    created_at: new Date('2024-02-01')
  },
  {
    id: 5,
    name: 'Online Shopping Scam',
    description: 'Fake online stores that take payment but never deliver goods, or sell counterfeit items.',
    warning_signs: 'Prices too good to be true, no contact information, poor website design, no customer reviews, payment only by wire transfer',
    example: 'Website selling designer goods at 90% discount with no return policy.',
    prevention_tips: 'Shop from reputable retailers, check reviews, use secure payment methods',
    created_at: new Date('2024-02-05')
  }
  // Add more types as needed
];

// === Analysis History === //
class AnalysisHistory {
  constructor() {
    this.storageKey = 'scamguard_analysis_history';
    this.maxEntries = 50;
  }

  addAnalysis(contentType, content, result) {
    const history = this.getHistory();
    const analysis = {
      id: Date.now(),
      content_type: contentType,
      content: content.slice(0, 100) + (content.length > 100 ? '...' : ''),
      risk_level: result.risk_level,
      risk_score: result.risk_score,
      detected_patterns: result.detected_patterns,
      analysis_details: result.analysis_details,
      created_at: new Date().toISOString()
    };
    history.unshift(analysis);
    if (history.length > this.maxEntries) history.splice(this.maxEntries);
    localStorage.setItem(this.storageKey, JSON.stringify(history));
    return analysis;
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

  getRecentAnalyses(limit = 5) {
    return this.getHistory().slice(0, limit);
  }

  clearHistory() {
    localStorage.removeItem(this.storageKey);
  }
}

// === Search Functionality === //
function searchScamTypes(query) {
  if (!query || query.trim() === '') return SCAM_TYPES;

  const searchTerm = query.toLowerCase().trim();
  return SCAM_TYPES.filter(scam => 
    scam.name.toLowerCase().includes(searchTerm) ||
    scam.description.toLowerCase().includes(searchTerm) ||
    scam.warning_signs.toLowerCase().includes(searchTerm) ||
    scam.prevention_tips.toLowerCase().includes(searchTerm)
  );
}

// === Educational Content === //
const EDUCATIONAL_CONTENT = {
  quickTips: [
    "Never share personal information via email or phone",
    "Verify URLs before clicking suspicious links",
    "Be skeptical of urgent or time-sensitive requests",
    "Contact organizations directly using official numbers",
    "Be cautious of unusual payment methods",
    "Discuss suspicious communications with trusted people"
  ],
  redFlags: [
    "Requests for immediate action or payment",
    "Unsolicited contact about problems or prizes",
    "Pressure to keep communication secret",
    "Requests for remote computer access",
    "Payment via gift cards, wire transfers, or cryptocurrency",
    "Too-good-to-be-true offers or guarantees",
    "Poor grammar, spelling, or generic greetings"
  ],
  greenFlags: [
    "Official contact information and websites",
    "Professional communication and branding",
    "No pressure for immediate decisions",
    "Secure payment methods with buyer protection",
    "Clear terms of service and refund policies",
    "Verifiable business registration and licenses",
    "Positive reviews from independent sources"
  ],
  actionSteps: [
    { step: 1, title: "Stop & Don't Respond", description: "Don't click links, provide info, or send money.", color: "primary" },
    { step: 2, title: "Verify Independently", description: "Contact organization directly using official info.", color: "warning" },
    { step: 3, title: "Report the Scam", description: "Report to authorities to protect others.", color: "success" }
  ],
  reportingResources: [
    { name: "FTC Fraud Reports", url: "https://reportfraud.ftc.gov/", icon: "external-link", color: "primary" },
    { name: "FBI IC3", url: "https://www.ic3.gov/", icon: "external-link", color: "warning" },
    { name: "FTC Scam Alerts", url: "https://www.consumer.ftc.gov/scam-alerts", icon: "external-link", color: "info" }
  ]
};

// === Export for frontend use === //
window.SCAM_TYPES = SCAM_TYPES;
window.AnalysisHistory = AnalysisHistory;
window.searchScamTypes = searchScamTypes;
window.EDUCATIONAL_CONTENT = EDUCATIONAL_CONTENT;

