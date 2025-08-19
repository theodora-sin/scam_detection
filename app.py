import os
from flask import Flask
from flask_socketio import SocketIO
from werkzeug.middleware.proxy_fix import ProxyFix

# Import from local files (no backend/ prefix)
from routes import init_routes
from configuration import Config   # ⚠️ fix typo if file is actually configuration.py

# ── Flask & SocketIO setup ─────────────────────────────
app = Flask(
    __name__,
    static_folder="../frontend",   # adjust if needed
    template_folder="../frontend"
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config.from_object(Config)

socketio = SocketIO(app, cors_allowed_origins="*")

# ── Initialize routes ─────────────────────────────────
init_routes(app)

# ── Socket events ─────────────────────────────────────
@socketio.on("connect")
def on_connect():
    socketio.emit("alert", {
        "message": "Connected to scam detection service",
        "type": "success"
    })

if __name__ == "__main__":
    print("🛡️ Scam Detection backend starting…")
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
