// Start Screen Controller
class StartScreen {
    constructor(app) {
        this.app = app;
        this.init();
    }

    init() {
        this.setupEventListeners();
    }

    setupEventListeners() {
        // Quick analysis form
        const quickForm = document.getElementById('quick-analysis-form');
        if (quickForm) {
            quickForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleQuickAnalysis(e.target);
            });
        }
    }

    handleQuickAnalysis(form) {
        const formData = new FormData(form);
        const contentType = formData.get('content_type');
        const content = formData.get('content');

        if (!content || !content.trim()) {
            this.app.showAlert('Please provide content to analyze.', 'warning');
            return;
        }

        this.performAnalysis(contentType, content, form, 'quick-results');
    }

    async performAnalysis(contentType, content, form, resultsContainerId) {
        const submitBtn = form.querySelector('button[type="submit"]');
        
        // Show loading state
        if (submitBtn) {
            this.showLoadingState(submitBtn);
        }

        try {
            // Perform analysis
            const result = this.app.analyzer.analyzeContent(content, contentType);
            console.log('Analysis completed:', result);
            
            // Save to history
            const analysisRecord = this.app.analysisHistory.addAnalysis(contentType, content, result);
            
            // Display results
            this.displayResults(analysisRecord || { content_type: contentType, content, ...result }, resultsContainerId);
            
            this.app.showAlert('Analysis completed successfully!', 'success');
        } catch (error) {
            console.error('Analysis error:', error);
            this.app.showAlert('An error occurred during analysis. Please try again.', 'danger');
        } finally {
            if (submitBtn) {
                this.hideLoadingState(submitBtn);
            }
        }
    }

    displayResults(analysis, containerId) {
        const resultsContainer = document.getElementById(containerId);
        if (!resultsContainer) return;

        const riskColorClass = analysis.risk_level === 'high' ? 'high' : 
                              analysis.risk_level === 'medium' ? 'medium' : 'low';

        resultsContainer.innerHTML = `
            <div class="risk-assessment risk-${riskColorClass}">
                <h3>📊 Quick Analysis Results</h3>
                <p><strong>Risk Level:</strong> ${(analysis.risk_level || analysis.level || 'unknown').toUpperCase()}</p>
                <p><strong>Risk Score:</strong> ${analysis.risk_score || analysis.score || 0}/100</p>
            </div>
            
            <div class="card">
                <h4>📋 Summary</h4>
                <p><strong>Content Type:</strong> ${(analysis.content_type || 'unknown').toUpperCase()}</p>
                <p><strong>Analyzed Content:</strong></p>
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 5px; margin: 1rem 0;">
                    <code>${this.app.escapeHtml(analysis.content || 'No content')}</code>
                </div>
                
                ${(analysis.detected_patterns || analysis.factors || []).length > 0 ? `
                    <h5>⚠️ Risk Indicators:</h5>
                    <ul>
                        ${(analysis.detected_patterns || analysis.factors || []).map(pattern => `<li>${pattern}</li>`).join('')}
                    </ul>
                ` : '<p>✅ No specific risk indicators detected.</p>'}
                
                <div style="margin-top: 1rem;">
                    <button class="btn btn-primary" onclick="app.showScreen('main')">🔍 View Detailed Analysis</button>
                </div>
            </div>
        `;

        resultsContainer.style.display = 'block';
    }

    showLoadingState(button) {
        if (button) {
            button.disabled = true;
            button.innerHTML = '<div class="loading"><div class="spinner"></div> Analyzing...</div>';
        }
    }

    hideLoadingState(button) {
        if (button) {
            button.disabled = false;
            button.innerHTML = '🔍 Analyze Content';
        }
    }

    activate() {
        // Called when start screen becomes active
        console.log('Start screen activated');
    }

    deactivate() {
        // Called when start screen becomes inactive
        console.log('Start screen deactivated');
    }
}
