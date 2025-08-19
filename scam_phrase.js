// === Global Constants === //
const SCAM_PHRASES = [
  "urgent action required", "act now or lose forever", "limited time offer", "expires today",
  "immediate response required", "time sensitive",
  "claim your prize", "congratulations! you have won", "you've been selected", "lottery winner",
  "cash prize", "free gift", "free money",
  "confirm your personal information", "verify your account", "update your details",
  "confirm your identity", "security verification required", "account suspended",
  "wire transfer", "send money", "pay processing fee", "tax refund", "inheritance money", "investment opportunity",
  "hsbc", "hm office", "google verification", "paypal security", "amazon security",
  "microsoft support", "apple support", "irs notice",
  "click to unlock", "download now", "install software", "run this file", "enable macros",
  "don't tell anyone", "confidential matter", "help me transfer money", "i am dying", "refugee", "widow"
];

const SUSPICIOUS_DOMAINS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
  "secure-bank", "paypal-secure", "amazon-security", "microsoft-support",
  "apple-security", "google-verify", "facebook-security", "tk", "xyz"
];

const LEGITIMATE_DOMAINS = [
  "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
  "facebook.com", "twitter.com", "linkedin.com", "github.com",
  "stackoverflow.com", "wikipedia.org", "reddit.com", "youtube.com",
  "gmail.com", "outlook.com"
];

// === URL Structure Checker === //
function checkUrlStructure(url) {
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname.toLowerCase();
    const path = parsed.pathname.toLowerCase();
    let suspiciousScore = 0;
    let issues = [];

    if (domain.length > 50) {
      suspiciousScore += 20;
      issues.push("Unusually long domain name");
    }

    if (/\d{4,}/.test(domain)) {
      suspiciousScore += 15;
      issues.push("Domain contains many numbers");
    }

    if (SUSPICIOUS_DOMAINS.some(short => domain.includes(short))) {
      suspiciousScore += 30;
      issues.push("Uses URL shortening service");
    }

    if ((domain.match(/\./g) || []).length > 2) {
      suspiciousScore += 10;
      issues.push("Multiple subdomains");
    }

    LEGITIMATE_DOMAINS.forEach(legit => {
      if (isSimilarDomain(domain, legit)) {
        suspiciousScore += 40;
        issues.push(`Domain similar to ${legit}`);
      }
    });

    const suspiciousPaths = ['login', 'verify', 'secure', 'update', 'confirm', 'account', 'billing', 'payment', 'suspended', 'locked'];
    suspiciousPaths.forEach(pattern => {
      if (path.includes(pattern)) {
        suspiciousScore += 5;
        issues.push(`Suspicious path contains: ${pattern}`);
      }
    });

    return {
      score: Math.min(suspiciousScore, 100),
      issues: issues,
      domain: domain,
      isShortener: SUSPICIOUS_DOMAINS.some(short => domain.includes(short))
    };

  } catch (e) {
    return { score: 50, issues: [`URL parsing error: ${e}`], domain: 'unknown' };
  }
}

function isSimilarDomain(d1, d2) {
  d1 = d1.replace(/\.(com|org|net|edu|gov|mil)$/, '');
  d2 = d2.replace(/\.(com|org|net|edu|gov|mil)$/, '');
  return calculateSimilarity(d1, d2) > 0.8 && d1 !== d2;
}

function calculateSimilarity(s1, s2) {
  const [longer, shorter] = s1.length >= s2.length ? [s1, s2] : [s2, s1];
  if (!longer) return 1.0;
  return (longer.length - levenshteinDistance(longer, shorter)) / longer.length;
}

function levenshteinDistance(a, b) {
  if (a.length < b.length) return levenshteinDistance(b, a);
  if (!b.length) return a.length;

  let prevRow = Array.from({ length: b.length + 1 }, (_, i) => i);

  for (let i = 0; i < a.length; i++) {
    let currRow = [i + 1];
    for (let j = 0; j < b.length; j++) {
      const insert = prevRow[j + 1] + 1;
      const del = currRow[j] + 1;
      const sub = prevRow[j] + (a[i] !== b[j] ? 1 : 0);
      currRow.push(Math.min(insert, del, sub));
    }
    prevRow = currRow;
  }

  return prevRow[b.length];
}
// Function to check URL structure
function checkUrlStructure(url) {
    let score = 0;
    try {
        let parsedUrl = new URL(url);

        // Check for suspicious patterns
        if (parsedUrl.hostname.includes('-') || parsedUrl.hostname.split('.').length > 3) {
            score += 20;
        }

        if (!parsedUrl.protocol.startsWith('https')) {
            score += 20;
        }
    } catch (error) {
        score += 40; // Invalid URL
    }
    return score;
}

// Function to check SSL certificate (simplified)
function checkSSL(url) {
    if (!url.startsWith('https')) {
        return 30; // No secure connection
    }
    return 0;
}

// Function to scrape and analyze content (basic keyword check)
function analyzeContent(content) {
    let score = 0;
    const suspiciousKeywords = ['free', 'win', 'click here', 'urgent', 'password', 'prize'];

    suspiciousKeywords.forEach(keyword => {
        if (content.toLowerCase().includes(keyword)) {
            score += 10;
        }
    });

    return score;
}

// Function to calculate overall risk
function calculateOverallRisk(url, content) {
    let score = 0;

    score += checkUrlStructure(url);
    score += checkSSL(url);
    score += analyzeContent(content);

    let riskLevel = '';
    if (score >= 60) {
        riskLevel = 'High Risk';
    } else if (score >= 40) {
        riskLevel = 'Medium Risk';
    } else {
        riskLevel = 'Low Risk';
    }

    return { score, riskLevel };
}

// Example usage
const testUrl = 'http://example-suspicious-site.com';
const testContent = 'Congratulations! Click here to win a free prize!';

const result = calculateOverallRisk(testUrl, testContent);
console.log('Overall Score:', result.score);
console.log('Risk Level:', result.riskLevel);

