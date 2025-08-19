from flask import request, jsonify
from urllib.parse import urlparse
import datetime

# Keywords + TLDs that trigger suspicion
SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "banking", "update"]
SUSPICIOUS_TLDS = [".ru", ".tk", ".cn"]

def basic_scan(url: str) -> dict:
    """Run a lightweight scam check on the given URL."""
    parsed = urlparse(url)

    score = 0
    reasons = []

    # Check protocol
    if not url.startswith("https://"):
        score += 20
        reasons.append("URL is not HTTPS secured")

    # Check length
    if len(url) > 100:
        score += 15
        reasons.append("URL is unusually long")

    # Check suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if parsed.netloc.endswith(tld):
            score += 25
            reasons.append(f"Suspicious domain ending ({tld})")

    # Check for suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            score += 20
            reasons.append(f"Contains suspicious keyword: {keyword}")

    # Cap score at 100
    score = min(score, 100)

    # Risk level mapping
    if score >= 80:
        level, color = "VERY HIGH", "danger"
    elif score >= 60:
        level, color = "HIGH", "danger"
    elif score >= 40:
        level, color = "MEDIUM", "warning"
    elif score >= 20:
        level, color = "LOW", "info"
    else:
        level, color = "MINIMAL", "success"

    return {
        "status": "ok",
        "url": url,
        "risk_assessment": {
            "score": score,
            "level": level,
            "color": color,
            "factors": reasons or ["No obvious scam signs detected"]
        },
        "timestamp_backend": datetime.datetime.utcnow().isoformat() + "Z"
    }

def init_routes(app):
    """Register Flask routes."""

    @app.route("/")
    def index():
        return app.send_static_file("index.html")

    @app.route("/scan_url", methods=["POST"])
    def scan_url():
        try:
            data = request.get_json(silent=True) or {}
            url = (data.get("url") or "").strip()
            if not url:
                return jsonify({"status": "error", "message": "No URL provided"}), 400

            # Default to https:// if missing
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            parsed = urlparse(url)
            if not parsed.netloc:
                return jsonify({"status": "error", "message": "Invalid URL format"}), 400

            results = basic_scan(url)
            return jsonify(results)

        except Exception as e:
            return jsonify({
                "status": "error",
                "message": str(e),
                "risk_assessment": {
                    "score": 50,
                    "level": "UNKNOWN",
                    "color": "secondary",
                    "factors": ["Analysis failed due to error"]
                }
            }), 500
