import re
import socket
import ssl
import datetime
from urllib.parse import urlparse
from typing import Dict, List

import requests

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except Exception:
    BS4_AVAILABLE = False

SCAM_PHRASES = [
    "urgent action required","act now or lose forever","limited time offer","expires today",
    "immediate response required","time sensitive","claim your prize","congratulations! you have won",
    "you've been selected","lottery winner","cash prize","free gift","free money","confirm your personal information",
    "verify your account","update your details","confirm your identity","security verification required",
    "account suspended","wire transfer","send money","pay processing fee","tax refund","inheritance money",
    "investment opportunity","hsbc","hm office","google verification","paypal security","amazon security",
    "microsoft support","apple support","irs notice","click to unlock","download now","install software",
    "run this file","enable macros","don't tell anyone","confidential matter","help me transfer money",
    "i am dying","refugee","widow"
]

SUSPICIOUS_DOMAINS = [
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","secure-bank","paypal-secure",
    "amazon-security","microsoft-support","apple-security","google-verify","facebook-security","tk","xyz"
]

LEGITIMATE_DOMAINS = [
    "google.com","microsoft.com","apple.com","amazon.com","paypal.com","facebook.com",
    "twitter.com","linkedin.com","github.com","stackoverflow.com","wikipedia.org","reddit.com",
    "youtube.com","gmail.com","outlook.com"
]

def check_url_structure(url: str) -> Dict:
    try:
        parsed = urlparse(url)
        domain, path = parsed.netloc.lower(), parsed.path.lower()
        suspicious_score, issues = 0, []

        if len(domain) > 50:
            suspicious_score += 20; issues.append("Unusually long domain name")
        if re.search(r'[0-9]{4,}', domain):
            suspicious_score += 15; issues.append("Domain contains many numbers")
        if any(x in domain for x in SUSPICIOUS_DOMAINS):
            suspicious_score += 30; issues.append("Uses URL shortening / suspicious domain")
        if domain.count('.') > 2:
            suspicious_score += 10; issues.append("Multiple subdomains")

        for legit in LEGITIMATE_DOMAINS:
            if is_similar_domain(domain, legit):
                suspicious_score += 40; issues.append(f"Domain similar to {legit}")

        suspicious_paths = ['login','verify','secure','update','confirm','account','billing','payment','suspended','locked']
        for p in suspicious_paths:
            if p in path:
                suspicious_score += 5; issues.append(f"Suspicious path contains: {p}")

        return {'score': min(suspicious_score, 100), 'issues': issues, 'domain': domain}
    except Exception as e:
        return {'score': 50, 'issues': [f"URL parsing error: {e}"], 'domain': 'unknown'}

def is_similar_domain(d1: str, d2: str) -> bool:
    try:
        d1 = re.sub(r'\.(com|org|net|edu|gov|mil)$', '', d1)
        d2 = re.sub(r'\.(com|org|net|edu|gov|mil)$', '', d2)
        return calculate_similarity(d1, d2) > 0.8 and d1 != d2
    except:
        return False

def calculate_similarity(a: str, b: str) -> float:
    longer, shorter = (a, b) if len(a) >= len(b) else (b, a)
    if not longer: return 1.0
    return (len(longer) - levenshtein_distance(longer, shorter)) / len(longer)

def levenshtein_distance(a: str, b: str) -> int:
    if len(a) < len(b): return levenshtein_distance(b, a)
    if not b: return len(a)
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a):
        cur = [i+1]
        for j, cb in enumerate(b):
            ins, dele = prev[j+1] + 1, cur[j] + 1
            sub = prev[j] + (ca != cb)
            cur.append(min(ins, dele, sub))
        prev = cur
    return prev[-1]

def check_ssl_certificate(url: str) -> Dict:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443
        if not hostname: return {'valid': False, 'issues': ['Invalid hostname'], 'score': 50}
        if parsed.scheme != 'https':
            return {'valid': False, 'issues': ['No HTTPS used'], 'score': 40}

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert: return {'valid': False, 'issues': ['No certificate found'], 'score': 60}
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days = (not_after - datetime.datetime.now()).days

                score, issues = 0, []
                if days < 30: score += 20; issues.append("SSL expires soon")
                subject = dict(x[0] for x in cert.get('subject', []))
                cert_domain = subject.get('commonName', '')
                if hostname not in cert_domain and not cert_domain.startswith('*.'):
                    score += 30; issues.append("SSL certificate domain mismatch")
                issuer = dict(x[0] for x in cert.get('issuer', [])).get('organizationName', 'Unknown')
                return {'valid': True, 'issues': issues, 'score': score,
                        'expires': not_after.strftime('%Y-%m-%d'), 'issuer': issuer}
    except Exception as e:
        return {'valid': False, 'issues': [f'SSL check failed: {e}'], 'score': 30}

def scrape_and_analyze_content(url: str) -> Dict:
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        resp = requests.get(url, headers=headers, timeout=15, verify=True)
        resp.raise_for_status()

        if not BS4_AVAILABLE:
            text = resp.text
            return {
                'scam_phrases': detect_scam_phrases(text),
                'suspicious_elements': [],
                'text_analysis': analyze_text_patterns(text),
                'content_preview': (text[:300] + '...') if len(text) > 300 else text,
                'note': 'Limited analysis - BeautifulSoup not available'
            }

        soup = BeautifulSoup(resp.content, 'html.parser')
        for tag in soup(['script','style','noscript']): tag.decompose()
        text = re.sub(r'\s+', ' ', soup.get_text()).strip()
        return {
            'scam_phrases': detect_scam_phrases(text),
            'suspicious_elements': analyze_html_elements(soup),
            'text_analysis': analyze_text_patterns(text),
            'content_preview': (text[:300] + '...') if len(text) > 300 else text
        }
    except requests.exceptions.RequestException as e:
        return {'error': f'Request failed: {e}', 'scam_phrases': [], 'suspicious_elements': [],
                'text_analysis': {}, 'content_preview': 'Could not load content'}
    except Exception as e:
        return {'error': str(e), 'scam_phrases': [], 'suspicious_elements': [],
                'text_analysis': {}, 'content_preview': 'Could not load content'}

def detect_scam_phrases(text: str) -> List[str]:
    if not text: return []
    lower = text.lower()
    return [p for p in SCAM_PHRASES if p in lower]

def analyze_html_elements(soup) -> List[str]:
    findings = []
    # hidden forms
    hidden_forms = soup.find_all('form', style=re.compile(r'display:\s*none', re.I))
    if hidden_forms: findings.append("Hidden forms detected")
    # suspicious iframes
    for iframe in soup.find_all('iframe'):
        src = iframe.get('src', '') or ''
        if any(d in src for d in SUSPICIOUS_DOMAINS):
            findings.append("Suspicious iframe source"); break
    # auto redirect
    if soup.find('meta', attrs={'http-equiv': 'refresh'}):
        findings.append("Auto-redirect detected")
    # suspicious links
    for a in soup.find_all('a', href=True):
        if any(d in a['href'] for d in SUSPICIOUS_DOMAINS):
            findings.append("Links to suspicious domains"); break
    return findings

def analyze_text_patterns(text: str) -> Dict:
    lower = (text or "").lower()
    urgency_words = ['urgent','immediate','quickly','asap','now','today','expires']
    money_words = ['$', 'money','cash','prize','million','fee']
    urgency = sum(lower.count(w) for w in urgency_words)
    money = sum(lower.count(w) for w in money_words)
    exclamations = text.count('!') if text else 0
    # naive misspellings
    common_misspellings = ['recieve','seperate','occured','goverment','beleive','neccessary',
                           'begining','existance','maintainance']
    words = re.findall(r'\b[a-zA-Z]+\b', lower)
    spelling_errors = sum(1 for w in words if w in common_misspellings)
    return {
        'urgency_score': min(urgency*10, 50),
        'money_focus_score': min(money*5, 30),
        'grammar_score': min(spelling_errors*3, 25),
        'excitement_score': min(exclamations*2, 20),
    }

def calculate_overall_risk(url_data: Dict, ssl_data: Dict, content_data: Dict) -> Dict:
    score = url_data.get('score', 0) + ssl_data.get('score', 0)
    factors = url_data.get('issues', []) + ssl_data.get('issues', [])

    phrases = content_data.get('scam_phrases', [])
    score += len(phrases) * 15
    if phrases:
        factors.append(f"Found {len(phrases)} scam phrases")

    elements = content_data.get('suspicious_elements', [])
    score += len(elements) * 10
    factors.extend(elements)

    for key, val in (content_data.get('text_analysis') or {}).items():
        score += int(val)
        if val > 15:
            factors.append(f"High {key.replace('_',' ')}")

    score = min(max(int(score), 0), 100)
    if score >= 80: level, color = 'VERY HIGH', 'danger'
    elif score >= 60: level, color = 'HIGH', 'danger'
    elif score >= 40: level, color = 'MEDIUM', 'warning'
    elif score >= 20: level, color = 'LOW', 'info'
    else: level, color = 'MINIMAL', 'success'

    return {'score': score, 'level': level, 'color': color, 'factors': factors[:10]}

def comprehensive_scan(url: str) -> Dict:
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    try:
        url_analysis = check_url_structure(url)
        ssl_analysis = check_ssl_certificate(url)
        content_analysis = scrape_and_analyze_content(url)
        risk = calculate_overall_risk(url_analysis, ssl_analysis, content_analysis)

        return {
            'status': 'success',
            'url': url,
            'timestamp': ts,
            'analyses': {
                'url_structure': url_analysis,
                'ssl_certificate': ssl_analysis,
                'content': content_analysis
            },
            'risk_assessment': risk
        }
    except Exception as e:
        return {
            'status': 'error',
            'url': url,
            'timestamp': ts,
            'risk_assessment': {
                'score': 50, 'level': 'UNKNOWN', 'color': 'secondary',
                'factors': [f'Analysis failed: {e}']
            }
        }
