from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
import os
import hashlib
from urllib.parse import urlparse
from Scam_phrase import comprehensive_scan 

# Import the VirusTotal function from your separate file
from scanningurl import check_url_virustotal

# Import your scam detection functions (if you have them)
try:
    from app import (
        detect_scam_phrases, 
        check_url_structure, 
        check_ssl_certificate,
        scrape_and_analyze_content
    )
    SCAM_DETECTION_AVAILABLE = True
except ImportError:
    SCAM_DETECTION_AVAILABLE = False
    print(" Scam detection module not found - using VirusTotal only")

# Initialize Flask app
app = Flask(__name__)

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_default_secret_key_for_scam_detector')
    DATABASE_URI = 'sqlite:///users.db'
    DEBUG = True

app.config.from_object(Config)
socketio = SocketIO(app, cors_allowed_origins="*")

def comprehensive_analysis(url):
    """Combine VirusTotal with other analysis methods"""
    results = {
        'url': url,
        'timestamp': datetime.datetime.now().isoformat() if 'datetime' in globals() else 'unknown',
        'analyses': {},
        'risk_assessment': {}
    }
    
    # VirusTotal analysis (from your separate file)
    print(f"🦠 Running VirusTotal scan for: {url}")
    virustotal_result = check_url_virustotal(url)
    results['analyses']['virustotal'] = virustotal_result
    
    # Additional analyses (if available)
    if SCAM_DETECTION_AVAILABLE:
        print("🔍 Running additional scam detection...")
        try:
            results['analyses']['url_structure'] = check_url_structure(url)
            results['analyses']['ssl_certificate'] = check_ssl_certificate(url)
            results['analyses']['content'] = scrape_and_analyze_content(url)
        except Exception as e:
            print("Additional analysis failed: {str(e)}")
    
    # Calculate overall risk assessment
    total_score = 0
    risk_factors = []
    
    # VirusTotal contribution (highest weight)
    vt_score = virustotal_result.get('score', 0)
    total_score += vt_score
    
    if virustotal_result.get('status') == 'dangerous':
        risk_factors.append(" Flagged as malicious by {virustotal_result.get('malicious_engines', 0)} security engines")
    elif virustotal_result.get('status') == 'suspicious':
        risk_factors.append(" Flagged as suspicious by {virustotal_result.get('suspicious_engines', 0)} security engines")
    elif virustotal_result.get('status') == 'safe':
        risk_factors.append(" Verified as safe by {virustotal_result.get('clean_engines', 0)} security engines")
    
    # Add other risk factors if available
    if SCAM_DETECTION_AVAILABLE and 'url_structure' in results['analyses']:
        url_score = results['analyses']['url_structure'].get('score', 0)
        total_score += url_score
        if url_score > 20:
            risk_factors.extend(results['analyses']['url_structure'].get('issues', []))
    
    # Determine final risk level
    if total_score >= 70:
        risk_level = 'VERY HIGH'
        color = 'danger'
    elif total_score >= 50:
        risk_level = 'HIGH'
        color = 'danger'
    elif total_score >= 30:
        risk_level = 'MEDIUM'
        color = 'warning'
    elif total_score >= 10:
        risk_level = 'LOW'
        color = 'info'
    else:
        risk_level = 'MINIMAL'
        color = 'success'
    
    results['risk_assessment'] = {
        'score': min(int(total_score), 100),
        'level': risk_level,
        'color': color,
        'factors': risk_factors[:10],
        'primary_engine': 'VirusTotal'
    }
    
    results['status'] = 'success'
    return results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan_url', methods=['POST'])
def scan_url():
    """Main scanning endpoint using your VirusTotal integration"""
    try:
        data = request.json
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({"status": "error", "message": "No URL provided"}), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Validate URL format
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                return jsonify({"status": "error", "message": "Invalid URL format"}), 400
        except:
            return jsonify({"status": "error", "message": "Invalid URL format"}), 400
        
        # Perform comprehensive analysis (VirusTotal + others)
        results = comprehensive_analysis(url)
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({
            "status": "error", 
            "message": str(e),
            "risk_assessment": {
                "score": 50,
                "level": "UNKNOWN",
                "color": "secondary",
                "factors": ["Analysis failed due to technical error"]
            }
        }), 500

@app.route('/virustotal_only', methods=['POST'])
def virustotal_only():
    """Endpoint for VirusTotal-only scanning"""
    try:
        data = request.json
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({"status": "error", "message": "No URL provided"}), 400
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Use your VirusTotal function directly
        result = check_url_virustotal(url)
        result['url'] = url
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'status': 'error', 'message': 'Username and password required'}), 400
        
        if len(password) < 6:
            return jsonify({'status': 'error', 'message': 'Password must be at least 6 characters'}), 400
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        return jsonify({'status': 'success', 'message': f'User {username} registered successfully!'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Registration failed: {str(e)}'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'status': 'error', 'message': 'Username and password required'}), 400
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        return jsonify({'status': 'success', 'message': f'Welcome back, {username}!'})
        
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Login failed: {str(e)}'}), 500

@socketio.on('connect')
def handle_connect():
    print('User connected to main scam detection service')
    emit('alert', {
        'message': 'Connected to advanced scam detection with VirusTotal integration',
        'type': 'success'
    })

@socketio.on('scan_request')
def handle_scan_request(data):
    """Real-time scanning using your VirusTotal integration"""
    try:
        url = data.get('url', '').strip()
        
        if not url:
            emit('scan_error', {'message': 'No URL provided'})
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Emit progress updates
        emit('scan_progress', {'stage': 'Starting comprehensive analysis...', 'progress': 10})
        emit('scan_progress', {'stage': 'Querying VirusTotal database...', 'progress': 40})
        
        if SCAM_DETECTION_AVAILABLE:
            emit('scan_progress', {'stage': 'Running additional security checks...', 'progress': 70})
        
        # Perform analysis using your VirusTotal function
        results = comprehensive_analysis(url)
        
        emit('scan_progress', {'stage': 'Analysis complete!', 'progress': 100})
        emit('scan_complete', results)
        
    except Exception as e:
        emit('scan_error', {'message': f'Scan failed: {str(e)}'})

if __name__ == '__main__':
    print("🛡️  Starting Main Scam Detection Website...")
    print("🦠 VirusTotal integration: ✅ Active")
    print(f"🔍 Additional scam detection: {'✅ Active' if SCAM_DETECTION_AVAILABLE else '❌ Not available'}")
    print("🌐 Server: http://localhost:5000")
    
    socketio.run(app, debug=Config.DEBUG, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
    
    emit('scan_complete', response)
if __name__ == '__main__':
    socketio.run(app, debug=True)
