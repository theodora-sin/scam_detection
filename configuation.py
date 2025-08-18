import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "scam-detector-secret-key-2024"
    DEBUG = True

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
    SECRET_KEY = os.environ.get("SECRET_KEY") or "set-a-strong-secret-in-prod"

class TestingConfig(Config):
    DEBUG = False

config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig
}

