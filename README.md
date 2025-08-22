Overview
ScamGuard is a Flask-based web application designed to detect and educate users about online scams. The application provides content analysis capabilities for URLs, emails, and messages, using pattern-matching algorithms to assess risk levels. It features a comprehensive educational component with a database of common scam types, warning signs, and prevention strategies.

User Preferences
Preferred communication style: Simple, everyday language.

System Architecture
Frontend Architecture
Template Engine: Jinja2 templates with Bootstrap 5 dark theme for responsive UI
Static Assets: Custom CSS and JavaScript for enhanced user experience
Icons: Feather Icons for consistent iconography
Forms: Multi-step content analysis forms with client-side validation
Backend Architecture
Framework: Flask with SQLAlchemy ORM for database operations
Application Factory Pattern: Centralized app configuration in app.py with modular imports
MVC Structure: Clear separation between models (models.py), views (templates), and controllers (routes.py)
Logging: Built-in Python logging for debugging and error tracking
Data Analysis Engine
Pattern Matching: Rule-based scam detection using regular expressions
Content Types: Specialized analysis for URLs, emails, and messages
Risk Scoring: Numerical scoring system with weighted pattern matches
Web Scraping: Trafilatura integration for URL content extraction
Database Design
ORM: SQLAlchemy with declarative base model
Models:
ScamType: Static scam type definitions with educational content
AnalysisResult: User-submitted analysis results and history
Initialization: Automatic seeding of scam type data on startup
Configuration: Flexible database URI with connection pooling
Analysis Logic
Multi-layered Detection: Different pattern sets for URLs, emails, and messages
Risk Categorization: Three-tier system (low, medium, high) based on cumulative scores
Legitimate Pattern Detection: Negative scoring for trusted indicators
Detailed Reporting: Comprehensive analysis results with detected patterns
External Dependencies
Core Framework Dependencies
Flask: Web framework and routing
SQLAlchemy: Database ORM and connection management
Werkzeug: WSGI utilities and proxy handling
Frontend Dependencies
Bootstrap 5: CSS framework delivered via CDN
Feather Icons: Icon library via CDN
Custom Assets: Local CSS and JavaScript files
Content Analysis
Trafilatura: Web content extraction and text processing
Python Standard Library: Regular expressions and URL parsing
Database Support
SQLite: Default local database (configurable via environment)
Connection Pooling: Built-in SQLAlchemy pool management
Environment Configuration: DATABASE_URL environment variable support
Development Tools
ProxyFix: Werkzeug middleware for deployment behind reverse proxies
Flask Debug Mode: Development server with auto-reload capabilities
