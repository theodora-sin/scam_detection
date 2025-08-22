// Main Application Logic - JavaScript Implementation
class ScamGuardApp {
    constructor() {
        this.analyzer = new ScamAnalyzer();
        this.analysisHistory = new AnalysisHistory();
        this.currentSection = 'home';
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadRecentAnalyses();
        this.showSection('home');
        this.updateActiveNavigation();
    }

    setupEventListeners() {
        // Navigation
        document.querySelectorAll('[data-section]').forEach(element => {
            element.addEventListener('click', (e) => {
                e.preventDefault();
                const section = element.getAttribute('data-section');
                this.showSection(section);
                this.updateActiveNavigation();
            });
        });

        // Quick analysis form
        const quickForm = document.getElementById('quick-analysis-form');
        if (quickForm) {
            quickForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleQuickAnalysis(e.target);
            });
        }

        // Main analysis form
        const analysisForm = document.getElementById('analysis-form');
        if (analysisForm) {
            analysisForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleAnalysis(e.target);
            });

            // Content type radio buttons
            const contentTypeRadios = analysisForm.querySelectorAll('input[name="content_type"]');
            contentTypeRadios.forEach(radio => {
                radio.addEventListener('change', () => {
                    this.updateTextareaForContentType(radio.value);
                });
            });
        }

        // Scam search
        const searchInput = document.getElementById('scam-search');
        const searchBtn = document.getElementById('search-btn');
        
        if (searchInput && searchBtn) {
            searchBtn.addEventListener('click', () => {
                this.searchScamTypes(searchInput.value);
            });

            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.searchScamTypes(searchInput.value);
                }
            });

            // Real-time search
            let searchTimeout;
            searchInput.addEventListener('input', () => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.searchScamTypes(searchInput.value);
                }, 300);
            });
        }

        // Handle hash changes for navigation
        window.addEventListener('hashchange', () => {
            const hash = window.location.hash.substring(1);
            if (hash) {
                this.showSection(hash);
                this.updateActiveNavigation();
            }
        });

        // Initialize with hash if present
        const initialHash = window.location.hash.substring(1);
        if (initialHash) {
            this.showSection(initialHash);
        }
    }

    showSection(sectionName) {
        // Hide all sections
        document.querySelectorAll('.page-section').forEach(section => {
            section.style.display = 'none';
        });

        // Show target section
        const targetSection = document.getElementById(`${sectionName}-section`);
        if (targetSection) {
            targetSection.style.display = 'block';
            this.currentSection = sectionName;
            
            // Update URL hash
            window.history.replaceState(null, '', `#${sectionName}`);
            
            // Load section-specific content
            this.loadSectionContent(sectionName);
        }
    }

    loadSectionContent(sectionName) {
        switch (sectionName) {
            case 'education':
                this.loadEducationContent();
                break;
            case 'scam-types':
                this.loadScamTypesContent();
                break;
        }
    }

    updateActiveNavigation() {
        // Remove active class from all nav links
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });

        // Add active class to current section
        document.querySelectorAll(`[data-section="${this.currentSection}"]`).forEach(link => {
            if (link.classList.contains('nav-link')) {
                link.classList.add('active');
            }
        });
    }

    handleQuickAnalysis(form) {
        const formData = new FormData(form);
        const contentType = formData.get('content_type');
        const content = formData.get('content');

        if (!contentType || !content.trim()) {
            this.showAlert('Please select a content type and provide content to analyze.', 'danger');
            return;
        }

        // Switch to analyze section and populate form
        this.showSection('analyze');
        
        const analysisForm = document.getElementById('analysis-form');
        if (analysisForm) {
            const radio = analysisForm.querySelector(`input[value="${contentType}"]`);
            if (radio) {
                radio.checked = true;
                this.updateTextareaForContentType(contentType);
            }
            
            const textarea = analysisForm.querySelector('textarea[name="content"]');
            if (textarea) {
                textarea.value = content;
            }
        }

        // Perform analysis
        this.performAnalysis(contentType, content);
    }

    handleAnalysis(form) {
        const formData = new FormData(form);
        const contentType = formData.get('content_type');
        const content = formData.get('content');

        if (!contentType || !content.trim()) {
            this.showAlert('Please select a content type and provide content to analyze.', 'danger');
            return;
        }

        this.performAnalysis(contentType, content);
    }

    performAnalysis(contentType, content) {
        // Show loading state
        const submitBtn = document.querySelector('#analysis-form button[type="submit"]');
        if (submitBtn) {
            this.showLoadingState(submitBtn);
        }

        try {
            // Perform analysis
            const result = this.analyzer.analyzeContent(content, contentType);
            
            // Save to history
            const analysisRecord = this.analysisHistory.addAnalysis(contentType, content, result);
            
            // Display results
            this.displayAnalysisResults(analysisRecord);
            
            // Update recent analyses
            this.loadRecentAnalyses();
            
            this.showAlert('Analysis completed successfully!', 'success');
        } catch (error) {
            console.error('Analysis error:', error);
            this.showAlert('An error occurred during analysis. Please try again.', 'danger');
        } finally {
            // Hide loading state
            if (submitBtn) {
                this.hideLoadingState(submitBtn);
            }
        }
    }

    displayAnalysisResults(analysis) {
        const resultsContainer = document.getElementById('analysis-results');
        if (!resultsContainer) return;

        const riskColorClass = analysis.risk_level === 'high' ? 'danger' : 
                              analysis.risk_level === 'medium' ? 'warning' : 'success';
        
        const riskIcon = analysis.risk_level === 'high' ? 'alert-triangle' : 
                        analysis.risk_level === 'medium' ? 'alert-circle' : 'check-circle';

        const resultsHTML = `
            <div class="mt-4">
                <!-- Risk Assessment Card -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h3 class="card-title mb-0 d-flex align-items-center">
                            <i data-feather="shield" class="me-2"></i>
                            Risk Assessment
                        </h3>
                    </div>
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-md-6">
                                <div class="alert alert-${riskColorClass} d-flex align-items-center">
                                    <i data-feather="${riskIcon}" class="me-2"></i>
                                    <div>
                                        <h4 class="alert-heading mb-1">${analysis.risk_level.toUpperCase()} RISK</h4>
                                        <p class="mb-0">
                                            ${analysis.risk_level === 'high' ? 'This content shows strong indicators of being a scam' :
                                              analysis.risk_level === 'medium' ? 'Exercise caution - this content has suspicious elements' :
                                              'This content appears relatively safe'}
                                        </p>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="text-center">
                                    <div class="risk-score-circle mb-2">
                                        <h2 class="display-4 fw-bold text-${riskColorClass}" id="risk-score-display">
                                            ${analysis.risk_score}
                                        </h2>
                                        <small class="text-muted">Risk Score (0-100)</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Content Details -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h4 class="card-title mb-0">
                            <i data-feather="eye" class="me-2"></i>
                            Analyzed Content
                        </h4>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <strong>Content Type:</strong>
                            <span class="badge bg-secondary ms-2">${analysis.content_type.charAt(0).toUpperCase() + analysis.content_type.slice(1)}</span>
                        </div>
                        <div class="mb-3">
                            <strong>Analyzed At:</strong>
                            <span class="text-muted">${new Date(analysis.created_at).toLocaleString()}</span>
                        </div>
                        <div>
                            <strong>Content:</strong>
                            <div class="bg-dark p-3 rounded mt-2 position-relative">
                                <code class="text-light">${this.escapeHtml(analysis.content)}</code>
                                <button class="btn btn-outline-secondary btn-sm position-absolute" 
                                        style="top: 10px; right: 10px;" 
                                        onclick="this.copyToClipboard('${this.escapeHtml(analysis.content)}')"
                                        title="Copy to clipboard">
                                    <i data-feather="copy"></i>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                ${analysis.detected_patterns.length > 0 ? `
                <!-- Detected Patterns -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h4 class="card-title mb-0">
                            <i data-feather="search" class="me-2"></i>
                            Detected Risk Indicators
                        </h4>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            ${analysis.detected_patterns.map(pattern => `
                                <div class="col-md-6 mb-3">
                                    <div class="d-flex align-items-start">
                                        <i data-feather="flag" class="text-warning me-2 mt-1 flex-shrink-0"></i>
                                        <span>${this.escapeHtml(pattern)}</span>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
                ` : ''}

                <!-- Detailed Analysis -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h4 class="card-title mb-0">
                            <i data-feather="file-text" class="me-2"></i>
                            Detailed Analysis & Recommendations
                        </h4>
                    </div>
                    <div class="card-body">
                        <pre class="text-wrap">${this.escapeHtml(analysis.analysis_details)}</pre>
                    </div>
                </div>

                <!-- Actions -->
                <div class="card">
                    <div class="card-header">
                        <h4 class="card-title mb-0">
                            <i data-feather="zap" class="me-2"></i>
                            What to Do Next
                        </h4>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <div class="d-grid">
                                    <button class="btn btn-primary" onclick="app.clearAnalysisForm()">
                                        <i data-feather="search" class="me-2"></i>
                                        Analyze Another Content
                                    </button>
                                </div>
                            </div>
                            <div class="col-md-6 mb-3">
                                <div class="d-grid">
                                    <button class="btn btn-outline-secondary" data-section="education">
                                        <i data-feather="book-open" class="me-2"></i>
                                        Learn About Scams
                                    </button>
                                </div>
                            </div>
                        </div>

                        <!-- Additional Resources -->
                        <div class="mt-4 pt-3 border-top">
                            <h6 class="mb-3">Additional Resources:</h6>
                            <div class="row">
                                <div class="col-md-4 mb-2">
                                    <button class="btn btn-outline-info btn-sm w-100" data-section="scam-types">
                                        <i data-feather="database" class="me-1"></i>
                                        Scam Database
                                    </button>
                                </div>
                                <div class="col-md-4 mb-2">
                                    <a href="https://reportfraud.ftc.gov/" target="_blank" class="btn btn-outline-warning btn-sm w-100">
                                        <i data-feather="external-link" class="me-1"></i>
                                        Report to FTC
                                    </a>
                                </div>
                                <div class="col-md-4 mb-2">
                                    <a href="https://www.ic3.gov/" target="_blank" class="btn btn-outline-danger btn-sm w-100">
                                        <i data-feather="external-link" class="me-1"></i>
                                        Report to FBI
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Disclaimer -->
                <div class="alert alert-info mt-4">
                    <h6 class="alert-heading">
                        <i data-feather="info" class="me-2"></i>
                        Disclaimer
                    </h6>
                    <p class="mb-0">
                        This analysis is provided for educational purposes only. While our system uses pattern matching 
                        to identify common scam indicators, it may not detect all scams or may occasionally flag legitimate 
                        content. Always use your judgment and verify suspicious content through official channels.
                    </p>
                </div>
            </div>
        `;

        resultsContainer.innerHTML = resultsHTML;
        resultsContainer.style.display = 'block';

        // Re-initialize icons and event listeners
        feather.replace();
        this.setupEventListeners();

        // Animate risk score
        this.animateRiskScore(document.getElementById('risk-score-display'), analysis.risk_score);

        // Scroll to results
        resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    clearAnalysisForm() {
        const form = document.getElementById('analysis-form');
        if (form) {
            form.reset();
            const resultsContainer = document.getElementById('analysis-results');
            if (resultsContainer) {
                resultsContainer.style.display = 'none';
            }
        }
    }

    loadRecentAnalyses() {
        const recentAnalyses = this.analysisHistory.getRecentAnalyses(5);
        const container = document.getElementById('recent-analyses-container');
        const section = document.getElementById('recent-analyses');
        
        if (!container || !section) return;

        if (recentAnalyses.length === 0) {
            section.style.display = 'none';
            return;
        }

        section.style.display = 'block';
        
        const analysesHTML = recentAnalyses.map(analysis => {
            const riskBadgeClass = analysis.risk_level === 'high' ? 'danger' : 
                                  analysis.risk_level === 'medium' ? 'warning' : 'success';
            
            return `
                <div class="col-md-6 col-lg-4 mb-3">
                    <div class="card">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-start mb-2">
                                <span class="badge bg-secondary">${analysis.content_type.charAt(0).toUpperCase() + analysis.content_type.slice(1)}</span>
                                <span class="badge bg-${riskBadgeClass}">
                                    ${analysis.risk_level.charAt(0).toUpperCase() + analysis.risk_level.slice(1)} Risk
                                </span>
                            </div>
                            <p class="card-text small text-muted mb-2">
                                ${analysis.content}
                            </p>
                            <small class="text-muted">
                                ${new Date(analysis.created_at).toLocaleDateString()} ${new Date(analysis.created_at).toLocaleTimeString()}
                            </small>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        container.innerHTML = analysesHTML;
    }

    loadEducationContent() {
        const container = document.getElementById('education-content');
        if (!container) return;

        const content = EDUCATIONAL_CONTENT;
        
        const educationHTML = `
            <!-- Quick Tips Section -->
            <div class="row mb-5">
                <div class="col-12">
                    <div class="card bg-primary text-white">
                        <div class="card-body">
                            <h3 class="card-title mb-4">
                                <i data-feather="lightbulb" class="me-2"></i>
                                Essential Scam Prevention Tips
                            </h3>
                            <div class="row">
                                <div class="col-md-6">
                                    <ul class="list-unstyled">
                                        ${content.quickTips.slice(0, 3).map(tip => `
                                            <li class="mb-2">
                                                <i data-feather="shield" class="me-2"></i>
                                                ${tip}
                                            </li>
                                        `).join('')}
                                    </ul>
                                </div>
                                <div class="col-md-6">
                                    <ul class="list-unstyled">
                                        ${content.quickTips.slice(3).map(tip => `
                                            <li class="mb-2">
                                                <i data-feather="shield" class="me-2"></i>
                                                ${tip}
                                            </li>
                                        `).join('')}
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Common Scam Types -->
            <div class="row mb-5">
                <div class="col-12">
                    <h2 class="mb-4">
                        <i data-feather="alert-triangle" class="text-warning me-2"></i>
                        Common Scam Types
                    </h2>
                    <div class="row">
                        ${SCAM_TYPES.slice(0, 6).map(scamType => `
                            <div class="col-lg-6 mb-4">
                                <div class="card h-100">
                                    <div class="card-header d-flex align-items-center">
                                        <i data-feather="alert-circle" class="text-danger me-2"></i>
                                        <h5 class="card-title mb-0">${scamType.name}</h5>
                                    </div>
                                    <div class="card-body">
                                        <p class="card-text">${scamType.description}</p>
                                        
                                        <h6 class="text-warning">
                                            <i data-feather="flag" class="me-1"></i>
                                            Warning Signs:
                                        </h6>
                                        <p class="small text-muted mb-3">${scamType.warning_signs}</p>
                                        
                                        ${scamType.example ? `
                                            <h6 class="text-info">
                                                <i data-feather="file-text" class="me-1"></i>
                                                Example:
                                            </h6>
                                            <p class="small font-italic mb-3">"${scamType.example}"</p>
                                        ` : ''}
                                        
                                        <h6 class="text-success">
                                            <i data-feather="shield" class="me-1"></i>
                                            Prevention:
                                        </h6>
                                        <p class="small">${scamType.prevention_tips}</p>
                                    </div>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>

            <!-- Red Flags Section -->
            <div class="row mb-5">
                <div class="col-md-6 mb-4">
                    <div class="card border-danger">
                        <div class="card-header bg-danger text-white">
                            <h4 class="card-title mb-0">
                                <i data-feather="x-circle" class="me-2"></i>
                                Red Flags - Avoid These!
                            </h4>
                        </div>
                        <div class="card-body">
                            <ul class="list-unstyled">
                                ${content.redFlags.map(flag => `
                                    <li class="mb-2">
                                        <i data-feather="alert-triangle" class="text-danger me-2"></i>
                                        ${flag}
                                    </li>
                                `).join('')}
                            </ul>
                        </div>
                    </div>
                </div>
                <div class="col-md-6 mb-4">
                    <div class="card border-success">
                        <div class="card-header bg-success text-white">
                            <h4 class="card-title mb-0">
                                <i data-feather="check-circle" class="me-2"></i>
                                Green Flags - These Are Good!
                            </h4>
                        </div>
                        <div class="card-body">
                            <ul class="list-unstyled">
                                ${content.greenFlags.map(flag => `
                                    <li class="mb-2">
                                        <i data-feather="check" class="text-success me-2"></i>
                                        ${flag}
                                    </li>
                                `).join('')}
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Action Steps -->
            <div class="row mb-5">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title mb-0">
                                <i data-feather="list" class="me-2"></i>
                                If You Suspect a Scam
                            </h3>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                ${content.actionSteps.map(step => `
                                    <div class="col-md-4">
                                        <div class="step-card text-center mb-4">
                                            <div class="step-number bg-${step.color} text-white rounded-circle mx-auto mb-3 d-flex align-items-center justify-content-center" style="width: 60px; height: 60px;">
                                                <h4 class="mb-0">${step.step}</h4>
                                            </div>
                                            <h5>${step.title}</h5>
                                            <p class="small">${step.description}</p>
                                        </div>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Reporting Resources -->
            <div class="row mb-5">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title mb-0">
                                <i data-feather="flag" class="me-2"></i>
                                Reporting Resources
                            </h3>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                ${content.reportingResources.map(resource => `
                                    <div class="col-md-3 mb-3">
                                        <a href="${resource.url}" target="_blank" class="btn btn-outline-${resource.color} w-100">
                                            <i data-feather="${resource.icon}" class="me-2"></i>
                                            ${resource.name}
                                        </a>
                                    </div>
                                `).join('')}
                                <div class="col-md-3 mb-3">
                                    <button class="btn btn-outline-success w-100" data-section="analyze">
                                        <i data-feather="search" class="me-2"></i>
                                        Analyze Content
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Additional Resources -->
            <div class="alert alert-info">
                <h5 class="alert-heading">
                    <i data-feather="book" class="me-2"></i>
                    Additional Resources
                </h5>
                <ul class="mb-0">
                    <li>Visit our <button class="btn btn-link p-0 align-baseline alert-link" data-section="scam-types">Scam Database</button> for detailed information about specific scam types</li>
                    <li>Use our <button class="btn btn-link p-0 align-baseline alert-link" data-section="analyze">Content Analysis Tool</button> to check suspicious URLs, emails, or messages</li>
                    <li>Stay informed about the latest scam trends and alerts from official government resources</li>
                    <li>Share this information with friends and family to help protect your community</li>
                </ul>
            </div>
        `;

        container.innerHTML = educationHTML;
        feather.replace();
        this.setupEventListeners();
    }

    loadScamTypesContent() {
        this.searchScamTypes(''); // Load all scam types initially
    }

    searchScamTypes(query = '') {
        const container = document.getElementById('scam-types-content');
        if (!container) return;

        const scamTypes = searchScamTypes(query);
        
        const searchInfo = query ? `
            <div class="row mb-3">
                <div class="col-12">
                    <div class="alert alert-info">
                        <i data-feather="info" class="me-2"></i>
                        Showing results for: <strong>"${this.escapeHtml(query)}"</strong>
                        (${scamTypes.length} result${scamTypes.length !== 1 ? 's' : ''} found)
                        <button class="btn btn-outline-primary btn-sm ms-3" onclick="document.getElementById('scam-search').value=''; app.searchScamTypes('');">
                            <i data-feather="x" class="me-1"></i>
                            Clear Search
                        </button>
                    </div>
                </div>
            </div>
        ` : '';

        const scamTypesHTML = scamTypes.length > 0 ? `
            <div class="row">
                ${scamTypes.map(scamType => `
                    <div class="col-lg-6 mb-4">
                        <div class="card h-100 border-warning">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="card-title mb-0 d-flex align-items-center">
                                    <i data-feather="alert-triangle" class="text-warning me-2"></i>
                                    ${scamType.name}
                                </h5>
                                <small class="text-muted">
                                    <i data-feather="calendar" class="me-1"></i>
                                    ${scamType.created_at.toLocaleDateString()}
                                </small>
                            </div>
                            <div class="card-body">
                                <!-- Description -->
                                <div class="mb-3">
                                    <h6 class="text-primary">
                                        <i data-feather="file-text" class="me-1"></i>
                                        Description
                                    </h6>
                                    <p class="card-text">${scamType.description}</p>
                                </div>

                                <!-- Warning Signs -->
                                <div class="mb-3">
                                    <h6 class="text-danger">
                                        <i data-feather="flag" class="me-1"></i>
                                        Warning Signs
                                    </h6>
                                    <p class="small">${scamType.warning_signs}</p>
                                </div>

                                <!-- Example (if available) -->
                                ${scamType.example ? `
                                    <div class="mb-3">
                                        <h6 class="text-info">
                                            <i data-feather="message-square" class="me-1"></i>
                                            Example
                                        </h6>
                                        <div class="bg-dark p-2 rounded">
                                            <small class="text-light font-italic">"${scamType.example}"</small>
                                        </div>
                                    </div>
                                ` : ''}

                                <!-- Prevention Tips -->
                                <div class="mb-0">
                                    <h6 class="text-success">
                                        <i data-feather="shield" class="me-1"></i>
                                        Prevention Tips
                                    </h6>
                                    <p class="small mb-0">${scamType.prevention_tips}</p>
                                </div>
                            </div>
                            <div class="card-footer bg-transparent">
                                <div class="d-flex justify-content-between align-items-center">
                                    <small class="text-muted">
                                        <i data-feather="info" class="me-1"></i>
                                        Stay vigilant and informed
                                    </small>
                                    <button class="btn btn-outline-primary btn-sm" data-section="analyze">
                                        <i data-feather="search" class="me-1"></i>
                                        Analyze Content
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        ` : `
            <div class="row">
                <div class="col-12">
                    <div class="text-center py-5">
                        <i data-feather="search" class="text-muted mb-3" style="width: 64px; height: 64px;"></i>
                        <h3 class="text-muted">No Results Found</h3>
                        <p class="lead text-muted mb-4">
                            No scam types match your search criteria.
                        </p>
                        <button class="btn btn-primary" onclick="document.getElementById('scam-search').value=''; app.searchScamTypes('');">
                            <i data-feather="database" class="me-2"></i>
                            View All Scam Types
                        </button>
                    </div>
                </div>
            </div>
        `;

        const statsHTML = `
            <!-- Quick Stats -->
            <div class="row mt-5">
                <div class="col-12">
                    <div class="card bg-secondary">
                        <div class="card-body text-center">
                            <div class="row">
                                <div class="col-md-4 mb-3 mb-md-0">
                                    <h3 class="mb-1">${scamTypes.length}</h3>
                                    <p class="mb-0">
                                        <i data-feather="database" class="me-1"></i>
                                        Scam Types ${query ? 'Found' : 'Documented'}
                                    </p>
                                </div>
                                <div class="col-md-4 mb-3 mb-md-0">
                                    <h3 class="mb-1">100%</h3>
                                    <p class="mb-0">
                                        <i data-feather="shield" class="me-1"></i>
                                        Prevention Focused
                                    </p>
                                </div>
                                <div class="col-md-4">
                                    <h3 class="mb-1">24/7</h3>
                                    <p class="mb-0">
                                        <i data-feather="clock" class="me-1"></i>
                                        Available Resource
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Call to Action -->
            <div class="row mt-4">
                <div class="col-12">
                    <div class="alert alert-primary">
                        <div class="d-flex align-items-center">
                            <i data-feather="lightbulb" class="me-3" style="width: 32px; height: 32px;"></i>
                            <div class="flex-grow-1">
                                <h5 class="alert-heading mb-1">Stay Protected</h5>
                                <p class="mb-2">
                                    Knowledge is your best defense. Use our analysis tool to check suspicious content 
                                    and learn more about scam prevention.
                                </p>
                                <div>
                                    <button class="btn btn-light btn-sm me-2" data-section="analyze">
                                        <i data-feather="search" class="me-1"></i>
                                        Analyze Content
                                    </button>
                                    <button class="btn btn-outline-light btn-sm" data-section="education">
                                        <i data-feather="book-open" class="me-1"></i>
                                        Learn More
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        container.innerHTML = searchInfo + scamTypesHTML + statsHTML;
        feather.replace();
        this.setupEventListeners();
    }

    updateTextareaForContentType(contentType) {
        const textarea = document.querySelector('textarea[name="content"]');
        if (!textarea) return;

        const placeholders = {
            'url': 'Enter the suspicious URL here...\n\nExample: https://suspicious-website.com/verify-account',
            'email': 'Paste the full email content here, including headers if available...\n\nInclude: sender, subject, and message body',
            'message': 'Paste the suspicious message or text here...\n\nCan be from SMS, social media, chat apps, etc.'
        };

        const rows = {
            'url': 3,
            'email': 10,
            'message': 6
        };

        if (placeholders[contentType] && rows[contentType]) {
            textarea.placeholder = placeholders[contentType];
            textarea.rows = rows[contentType];
            textarea.focus();
        }
    }

    showAlert(message, type = 'info') {
        const container = document.getElementById('alert-container');
        if (!container) return;

        const alertId = 'alert-' + Date.now();
        const alertHTML = `
            <div id="${alertId}" class="alert alert-${type} alert-dismissible fade show" role="alert">
                ${this.escapeHtml(message)}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        `;

        container.insertAdjacentHTML('beforeend', alertHTML);

        // Auto-dismiss after 5 seconds for success/error messages
        if (type === 'success' || type === 'danger') {
            setTimeout(() => {
                const alert = document.getElementById(alertId);
                if (alert) {
                    const bsAlert = new bootstrap.Alert(alert);
                    bsAlert.close();
                }
            }, 5000);
        }
    }

    showLoadingState(button) {
        if (!button) return;
        
        button.disabled = true;
        const originalText = button.innerHTML;
        button.setAttribute('data-original-text', originalText);
        button.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Analyzing...';
    }

    hideLoadingState(button) {
        if (!button) return;
        
        button.disabled = false;
        const originalText = button.getAttribute('data-original-text');
        if (originalText) {
            button.innerHTML = originalText;
            feather.replace();
        }
    }

    animateRiskScore(element, finalScore) {
        if (!element) return;
        
        const duration = 1500; // 1.5 seconds
        const startTime = Date.now();
        
        const updateScore = () => {
            const currentTime = Date.now();
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            // Ease out animation
            const easeOut = 1 - Math.pow(1 - progress, 3);
            const currentScore = Math.floor(easeOut * finalScore);
            
            element.textContent = currentScore;
            
            if (progress < 1) {
                requestAnimationFrame(updateScore);
            } else {
                element.textContent = finalScore;
            }
        };
        
        element.textContent = '0';
        requestAnimationFrame(updateScore);
    }

    copyToClipboard(text) {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(() => {
                this.showAlert('Content copied to clipboard!', 'success');
            }).catch(() => {
                this.showAlert('Failed to copy to clipboard', 'danger');
            });
        } else {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                this.showAlert('Content copied to clipboard!', 'success');
            } catch (err) {
                this.showAlert('Failed to copy to clipboard', 'danger');
            }
            document.body.removeChild(textArea);
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize the application
let app;
document.addEventListener('DOMContentLoaded', function() {
    app = new ScamGuardApp();
    
    // Make app globally available for inline event handlers
    window.app = app;
    
    // Auto-dismiss alerts
    const alerts = document.querySelectorAll('.alert:not(.alert-info):not(.alert-primary)');
    alerts.forEach(function(alert) {
        if (alert.classList.contains('alert-success') || alert.classList.contains('alert-danger')) {
            setTimeout(function() {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }, 5000);
        }
    });

    // External link handling
    document.addEventListener('click', function(e) {
        const link = e.target.closest('a[href^="http"]:not([href*="' + location.hostname + '"])');
        if (link && !link.hasAttribute('data-confirmed')) {
            e.preventDefault();
            if (confirm('This link will open in a new tab. Are you sure you want to continue?')) {
                link.setAttribute('data-confirmed', 'true');
                window.open(link.href, '_blank', 'noopener,noreferrer');
            }
        }
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        if (e.altKey) {
            switch (e.key) {
                case 'a':
                    e.preventDefault();
                    app.showSection('analyze');
                    break;
                case 'e':
                    e.preventDefault();
                    app.showSection('education');
                    break;
                case 'd':
                    e.preventDefault();
                    app.showSection('scam-types');
                    break;
                case 'h':
                    e.preventDefault();
                    app.showSection('home');
                    break;
            }
        }
    });
});
