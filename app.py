import os
import datetime
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template
from flask_socketio import SocketIO, emit
from werkzeug.middleware.proxy_fix import ProxyFix

from scamdetection import comprehensive_scan
from scanningurl import check_url_virustotal

# ── Flask & SocketIO ────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="static", template_folder="templates")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "scam-detector-secret-key-2024")
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "1") == "1"

socketio = SocketIO(app, cors_allowed_origins="*")

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    # Serves templates/index.html
    return render_template("index.html")

@app.route("/scan_url", methods=["POST"])
def scan_url():
    from flask import request
    try:
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()
        if not url:
            return jsonify({"status": "error", "message": "No URL provided"}), 400

        # Add protocol if missing
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        # Validate parse
        parsed = urlparse(url)
        if not parsed.netloc:
            return jsonify({"status": "error", "message": "Invalid URL format"}), 400

        # Run comprehensive scan (URL structure + SSL + content) + VT if configured
        results = comprehensive_scan(url)

        vt_api = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
        if vt_api:
            vt_result = check_url_virustotal(url, api_key=vt_api)
            results["analyses"]["virustotal"] = vt_result
            # Blend VT score lightly into overall score (cap after sum)
            vt_score = max(0, min(int(vt_result.get("score", 0)), 100))
            base = results["risk_assessment"]["score"]
            blended = min(base + int(vt_score * 0.35), 100)
            results["risk_assessment"]["score"] = blended
            # bump level if needed
            s = blended
            if s >= 80: lvl, color = "VERY HIGH", "danger"
            elif s >= 60: lvl, color = "HIGH", "danger"
            elif s >= 40: lvl, color = "MEDIUM", "warning"
            elif s >= 20: lvl, color = "LOW", "info"
            else: lvl, color = "MINIMAL", "success"
            results["risk_assessment"]["level"] = lvl
            results["risk_assessment"]["color"] = color

        results["timestamp_backend"] = datetime.datetime.utcnow().isoformat() + "Z"
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

# ── Socket events (optional) ───────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    emit("alert", {"message": "Connected to scam detection service", "type": "success"})

if __name__ == "__main__":
    print("🛡️  Scam Detection backend starting…")
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
