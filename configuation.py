import os
from ipaddress import ip_network

class Config:
    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "scam-detector-secret-key-2024")
    DEBUG = os.environ.get("FLASK_DEBUG", "1") == "1"

    # Networking / security
    ALLOWED_SCHEMES = {"http", "https"}
    REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "15"))
    MAX_DOWNLOAD_BYTES = int(os.environ.get("MAX_DOWNLOAD_BYTES", "1048576"))  # 1 MB max fetch
    USER_AGENT = os.environ.get("USER_AGENT", "ScamDetector/1.0 (+https://example.invalid)")

    # Block SSRF to internal networks
    BLOCKED_NETS = [
        ip_network("127.0.0.0/8"),
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
        ip_network("192.168.0.0/16"),
        ip_network("169.254.0.0/16"),
        ip_network("0.0.0.0/8"),
        ip_network("::1/128"),
        ip_network("fc00::/7"),
        ip_network("fe80::/10"),
    ]

class ProductionConfig(Config):
    DEBUG = False
    SECRET_KEY = os.environ.get("SECRET_KEY") or "set-a-strong-secret-in-prod"

class TestingConfig(Config):
    DEBUG = False
