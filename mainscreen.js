// Main Analysis Screen Controller
class MainScreen {
    constructor(app) {
        this.app = app;
        this.init();
    }

    init() {
        this.setupEventListeners();
    }

    setupEventListeners() {
        // Detailed analysis form
        const analysisForm = document.getElementById('analysis-form');
        if (analysisForm) {
            analysisForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleDetailedAnalysis(e.target);
            });
        }

        // Clear history button
        const clearHistoryBtn = document.getElementById('clear-history-btn');
        if (clearHistoryBtn) {
            clearHistoryBtn.addEventListener('click', () => {
                this.clearHistory();
            });
        }
    }

    handleDetailedAnalysis(form) {
        const formData = new FormData(form);
        const contentType = formData.get('content_type');
        const content = formData.get('content');

        if (!content || !content.trim()) {
            this.app.showAlert('Please provide content to analyze.', 'warning');
            return;
        }

        this.performAnalysis(contentType, content, form, 'analysis-results');
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
            console.log('Detailed analysis completed:', result);
            
            // Save to history
            const analysisRecord = this.app.analysisHistory.addAnalysis(contentType, content, result);
            
            // Display results
            this.displayDetailedResults(analysisRecord || { content_type: contentType, content, ...result }, resultsContainerId);
            
            // Update history display
            this.loadAnalysisHistory();
            
            this.app.showAlert('Detailed analysis completed successfully!', 'success');
        } catch (error) {
            console.error('Analysis error:', error);
            this.app.showAlert('An error occurred during analysis. Please try again.', 'danger');
        } finally {
            if (submitBtn) {
                this.hideLoadingState(submitBtn);
            }
        }
    }

    displayDetailedResults(analysis, containerId) {
        const resultsContainer = document.getElementById(containerId);
        if (!resultsContainer) return;

        const riskColorClass = analysis.risk_level === 'high' ? 'high' : 
                              analysis.risk_level === 'medium' ? 'medium' : 'low';

        resultsContainer.innerHTML = `
            <div class="risk-assessment risk-${riskColorClass}">
                <h3>📊 Detailed Risk Assessment</h3>
                <p><strong>Risk Level:</strong> ${(analysis.risk_level || analysis.level || 'unknown').toUpperCase()}</p>
                <p><strong>Risk Score:</strong> ${analysis.risk_score || analysis.score || 0}/100</p>
                <p><strong>Analysis ID:</strong> ${analysis.id || 'N/A'}</p>
            </div>
            
            <div class="card">
                <h4>📋 Complete Analysis Report</h4>
                <p><strong>Content Type:</strong> ${(analysis.content_type || 'unknown').toUpperCase()}</p>
                <p><strong>Analyzed Content:</strong></p>
                <div style="background: #f8f9fa; padding: 1rem; border-radius: 5px; margin: 1rem 0;">
                    <code>${this.app.escapeHtml(analysis.content || 'No content')}</code>
                </div>
                
                ${(analysis.detected_patterns || analysis.factors || []).length > 0 ? `
                    <h5>⚠️ Risk Indicators Found:</h5>
                    <ul>
                        ${(analysis.detected_patterns || analysis.factors || []).map(pattern => `<li>${pattern}</li>`).join('')}
                    </ul>
                ` : '<p>✅ No specific risk indicators detected.</p>'}
                
                <h5>📝 Detailed Analysis Report:</h5>
                <pre style="white-space: pre-wrap; background: #f8f9fa; padding: 1rem; border-radius: 5px; font-size: 0.9rem;">${analysis.analysis_details || analysis.details || 'No details available'}</pre>
                
                <div style="margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid #dee2e6;">
                    <small>📅 Analysis completed: ${analysis.created_at ? new Date(analysis.created_at).toLocaleString() : new Date().toLocaleString()}</small>
                </div>
            </div>
        `;

        resultsContainer.style.display = 'block';
    }

    loadAnalysisHistory() {
        const historyContainer = document.getElementById('analysis-history');
        if (!historyContainer) return;

        const history = this.app.analysisHistory.getHistory();
        
        if (history.length === 0) {
            historyContainer.innerHTML = '<p>No analysis history found. Start by analyzing some content!</p>';
            return;
        }

        historyContainer.innerHTML = history.slice(0, 10).map(analysis => `
            <div class="history-item" onclick="this.classList.toggle('expanded')">
                <h4>${(analysis.content_type || 'unknown').toUpperCase()} Analysis</h4>
                <p><strong>Content:</strong> ${this.app.escapeHtml(analysis.content || 'No content')}</p>
                <div class="history-meta">
                    <span><strong>Risk Level:</strong> ${(analysis.risk_level || 'unknown').toUpperCase()}</span> | 
                    <span><strong>Score:</strong> ${analysis.risk_score || 0}/100</span> | 
                    <span><strong>Date:</strong> ${analysis.created_at ? new Date(analysis.created_at).toLocaleDateString() : 'Unknown'}</span>
                </div>
                
                ${analysis.detected_patterns && analysis.detected_patterns.length > 0 ? `
                    <div style="margin-top: 0.5rem; font-size: 0.875rem;">
                        <strong>Indicators:</strong> ${analysis.detected_patterns.slice(0, 3).join(', ')}${analysis.detected_patterns.length > 3 ? '...' : ''}
                    </div>
                ` : ''}
            </div>
        `).join('');
    }

    clearHistory() {
        if (confirm('Are you sure you want to clear all analysis history? This action cannot be undone.')) {
            const success = this.app.analysisHistory.clearHistory();
            if (success) {
                this.loadAnalysisHistory();
                this.app.showAlert('Analysis history cleared successfully!', 'success');
            } else {
                this.app.showAlert('Failed to clear history. Please try again.', 'danger');
            }
        }
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
            button.innerHTML = '🔍 Perform Detailed Analysis';
        }
    }

    activate() {
        // Called when main screen becomes active
        console.log('Main screen activated');
        this.loadAnalysisHistory();
    }

    deactivate() {
        // Called when main screen becomes inactive
        console.log('Main screen deactivated');
    }
}
