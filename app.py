from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
import requests
import base64
import re
import nltk
from bs4 import BeautifulSoup
from urllib.parse import urlparse
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
# Enhanced scam phrases (use the expanded list above)
scam_phrases = [
    "urgent action required",
    "claim your prize",
    "congratulations! you have won",
    "confirm your personal information",
    "limited time offer",
    "hsbc",
    "click to unlock",
    "verify your account",
    "account suspended",
    "wire transfer",
    "lottery winner",
    "inheritance money",
    "tax refund",
    "microsoft support",
    "paypal security",
    "download now",
    "install software",
    "confidential matter"
]
def check_url_virustotal(url):
    """Check URL using VirusTotal API"""
    api_key = ""  # Replace with your actual API key
    
    if not api_key:
        return {'status': 'error', 'details': 'VirusTotal API key not configured'}
    
    try:
        # Base64 encode the URL
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {'x-apikey': api_key}
        
        # Make API request to VirusTotal
        response = requests.get(f'https://www.virustotal.com/api/v3/urls/{encoded_url}', headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            
            if 'data' in result:
                analysis_stats = result['data']['attributes']['last_analysis_stats']
                
                if analysis_stats['malicious'] > 0:
                    return {'status': 'dangerous', 'details': analysis_stats}
                else:
                    return {'status': 'safe', 'details': analysis_stats}
            else:
                return {'status': 'unknown', 'details': 'No analysis data available'}
        else:
            return {'status': 'error', 'details': f'API request failed: {response.status_code}'}
            
    except Exception as e:
        return {'status': 'error', 'details': str(e)}
def check_url_google_safe_browsing(url):
    """Check URL using Google Safe Browsing API"""
    api_key = ""  # Replace with your Google API key
    
    if not api_key:
        return {'status': 'error', 'details': 'Google Safe Browsing API key not configured'}
    
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        
        payload = {
            "client": {"clientId": "scam-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        headers = {"Content-Type": "application/json"}
        
        response = requests.post(api_url, json=payload, headers=headers)
        result = response.json()
        if "matches" in result:
            return {"status": "dangerous", "details": result["matches"]}
        else:
            return {"status": "safe", "details": None}
            
    except Exception as e:
        return {"status": "error", "details": str(e)}
def scrape_website_content(url):
    """Scrape website content for analysis"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
        
        # Get text content
        text = soup.get_text()
        
        # Clean up whitespace
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = ' '.join(chunk for chunk in chunks if chunk)
        
        return text[:5000]  # Limit to first 5000 characters
        
    except Exception as e:
        return f"Error scraping content: {str(e)}"
def detect_scam_phrases(text):
    """Detect scam-related phrases in the given text"""
    found_phrases = []
    for phrase in scam_phrases:
        if re.search(r"\b" + re.escape(phrase) + r"\b", text, re.IGNORECASE):
            found_phrases.append(phrase)
    return found_phrases
def calculate_risk_score(virustotal_result, google_result, scam_phrases_found):
    """Calculate overall risk score"""
    risk_score = 0
    risk_factors = []
    
    # VirusTotal analysis
    if virustotal_result['status'] == 'dangerous':
        risk_score += 50
        risk_factors.append("Flagged by VirusTotal")
    elif virustotal_result['status'] == 'safe':
        risk_score -= 10
    
    # Google Safe Browsing analysis
    if google_result['status'] == 'dangerous':
        risk_score += 40
        risk_factors.append("Flagged by Google Safe Browsing")
    elif google_result['status'] == 'safe':
        risk_score -= 5
    
    # Scam phrases
    phrase_score = len(scam_phrases_found) * 8
    risk_score += phrase_score
    
    if scam_phrases_found:
        risk_factors.append(f"Contains {len(scam_phrases_found)} suspicious phrases")
    
    # Determine risk level
    if risk_score >= 50:
        risk_level = 'HIGH'
    elif risk_score >= 25:
        risk_level = 'MEDIUM'
    elif risk_score >= 10:
        risk_level = 'LOW'
    else:
        risk_level = 'MINIMAL'
    
    return {
        'score': max(0, min(100, risk_score)),
        'level': risk_level,
        'factors': risk_factors
    }
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/scan_url', methods=['POST'])
def scan_url():
    """Comprehensive URL scanning endpoint"""
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({"status": "error", "message": "No URL provided"}), 400
    
    # Validate URL format
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return jsonify({"status": "error", "message": "Invalid URL format"}), 400
    except:
        return jsonify({"status": "error", "message": "Invalid URL format"}), 400
    
    try:
        # Run all checks
        virustotal_result = check_url_virustotal(url)
        google_result = check_url_google_safe_browsing(url)
        
        # Scrape website content
        website_content = scrape_website_content(url)
        
        # Detect scam phrases
        scam_phrases_found = detect_scam_phrases(website_content)
        
        # Calculate overall risk
        risk_assessment = calculate_risk_score(virustotal_result, google_result, scam_phrases_found)
        
        # Prepare response
        response = {
            "status": "success",
            "url": url,
            "analysis": {
                "virustotal": virustotal_result,
                "google_safe_browsing": google_result,
                "scam_phrases": scam_phrases_found,
                "content_preview": website_content[:200] + "..." if len(website_content) > 200 else website_content
            },
            "risk_assessment": risk_assessment
        }
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
# WebSocket events for real-time updates
@socketio.on('scan_request')
def handle_scan_request(data):
    url = data['url']
    
    # Emit progress updates
    emit('scan_progress', {'stage': 'Starting scan...', 'progress': 10})
    
    # VirusTotal check
    emit('scan_progress', {'stage': 'Checking VirusTotal...', 'progress': 30})
    virustotal_result = check_url_virustotal(url)
    
    # Google Safe Browsing check
    emit('scan_progress', {'stage': 'Checking Google Safe Browsing...', 'progress': 50})
    google_result = check_url_google_safe_browsing(url)
    
    # Content analysis
    emit('scan_progress', {'stage': 'Analyzing website content...', 'progress': 70})
    website_content = scrape_website_content(url)
    scam_phrases_found = detect_scam_phrases(website_content)
    
    # Final analysis
    emit('scan_progress', {'stage': 'Calculating risk assessment...', 'progress': 90})
    risk_assessment = calculate_risk_score(virustotal_result, google_result, scam_phrases_found)
    
    # Send final results
    emit('scan_progress', {'stage': 'Complete!', 'progress': 100})
    
    response = {
        "url": url,
        "analysis": {
            "virustotal": virustotal_result,
            "google_safe_browsing": google_result,
            "scam_phrases": scam_phrases_found
        },
        "risk_assessment": risk_assessment
    }
    
    emit('scan_complete', response)
if __name__ == '__main__':
    socketio.run(app, debug=True)
