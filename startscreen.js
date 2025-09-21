// Start Screen Controller - Based on your original startscreen_1755844201663.js
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

        // Radio button styling for content type selection
        const radioInputs = quickForm?.querySelectorAll('input[type="radio"]');
        if (radioInputs) {
            radioInputs.forEach(input => {
                input.addEventListener('change', (e) => {
                    this.updateRadioStyles(e.target);
                });
            });
            // Set initial style
            const checkedInput = quickForm.querySelector('input[type="radio"]:checked');
            if (checkedInput) this.updateRadioStyles(checkedInput);
        }
    }

    updateRadioStyles(selectedInput) {
        const form = selectedInput.closest('form');
        const labels = form.querySelectorAll('.radio-option label');
        
        labels.forEach(label => {
            label.classList.remove('border-neon-cyan', 'bg-neon-cyan/10', 'text-neon-cyan');
            label.classList.add('border-gray-600', 'text-white');
        });
        
        const selectedLabel = selectedInput.nextElementSibling;
        if (selectedLabel) {
            selectedLabel.classList.remove('border-gray-600', 'text-white');
            selectedLabel.classList.add('border-neon-cyan', 'bg-neon-cyan/10', 'text-neon-cyan');
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
            // Simulate scanning delay like original
            await new Promise(resolve => setTimeout(resolve, 2000));
            
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

        const riskColorClass = this.getRiskColorClass(analysis.risk_level || analysis.level);

        resultsContainer.innerHTML = `
            <div class="risk-assessment ${riskColorClass} p-6 rounded-lg border-2 mb-6">
                <h3 class="text-xl font-bold mb-3">📊 Quick Analysis Results</h3>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                        <p class="text-sm opacity-75">Risk Level</p>
                        <p class="text-2xl font-bold">${(analysis.risk_level || analysis.level || 'unknown').toUpperCase()}</p>
                    </div>
                    <div>
                        <p class="text-sm opacity-75">Risk Score</p>
                        <p class="text-2xl font-bold">${analysis.risk_score || analysis.score || 0}/100</p>
                    </div>
                </div>
            </div>
            
            <div class="card" style="background: none !important; border: none !important; box-shadow: none !important;">
                <div class="p-6">
                    <h4 class="text-lg font-bold text-white mb-4">📋 Analysis Summary</h4>
                    <p class="text-gray-300 mb-3"><strong>Content Type:</strong> ${(analysis.content_type || 'unknown').toUpperCase()}</p>
                    <p class="text-gray-300 mb-3"><strong>Analyzed Content:</strong></p>
                    <div style="background: none !important; border: none !important; box-shadow: none !important; padding: 1rem; border-radius: 0; margin-bottom: 1rem;">
                        <code class="text-gray-200 text-sm font-mono break-all">${this.app.escapeHtml(analysis.content || 'No content')}</code>
                    </div>
                    ${(analysis.detected_patterns || analysis.factors || []).length > 0 ? `
                        <h5 class="text-white font-semibold mb-2">⚠️ Risk Indicators:</h5>
                        <ul class="space-y-2 mb-4">
                            ${(analysis.detected_patterns || analysis.factors || []).map(pattern => `
                                <li class="flex items-start space-x-2">
                                    <span class="text-neon-orange mt-1">•</span>
                                    <span class="text-gray-300 text-sm">${pattern}</span>
                                </li>
                            `).join('')}
                        </ul>
                    ` : '<p class="text-green-400 mb-4">✅ No specific risk indicators detected.</p>'}
                    <div class="mt-6 pt-4 border-t border-gray-700">
                        <button class="text-lg font-bold text-white mb-4"onclick="app.showScreen('main')">
                            🔍 View Detailed Analysis
                        </button>
                    </div>
                </div>
            </div>
        `;

        resultsContainer.style.display = 'block';
    }

    getRiskColorClass(level) {
        switch ((level || '').toLowerCase()) {
            case 'high': return 'border-red-500 bg-red-900/20 text-red-300';
            case 'medium': return 'border-yellow-500 bg-yellow-900/20 text-yellow-300';
            case 'low': return 'border-green-500 bg-green-900/20 text-green-300';
            default: return 'border-gray-500 bg-gray-900/20 text-gray-300';
        }
    }

    showLoadingState(button) {
        if (button) {
            button.disabled = true;
            button.innerHTML = '<div class="flex items-center justify-center space-x-2"><div class="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div><span>Analyzing...</span></div>';
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
