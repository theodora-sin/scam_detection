// Main Application Controller
class ScamDetectionApp {
    constructor() {
        this.analyzer = new ScamAnalyzer();
        this.analysisHistory = new AnalysisHistory();
        this.currentScreen = 'start';
        this.screens = {};
        
        this.init();
    }

    init() {
        // Initialize screen controllers
        this.screens.start = new StartScreen(this);
        this.screens.main = new MainScreen(this);
        this.screens.education = new EducationScreen(this);
        
        this.setupNavigation();
        this.showScreen('start');
        this.updateActiveNavigation();
        
        console.log('Scam Detection App initialized successfully');
    }

    setupNavigation() {
        // Navigation event listeners
        document.querySelectorAll('[data-screen]').forEach(element => {
            element.addEventListener('click', (e) => {
                e.preventDefault();
                const screen = element.getAttribute('data-screen');
                this.showScreen(screen);
                this.updateActiveNavigation();
            });
        });
    }

    showScreen(screenName) {
        // Hide all screens
        document.querySelectorAll('.screen').forEach(screen => {
            screen.classList.remove('active');
        });

        // Show target screen
        const targetScreen = document.getElementById(`${screenName}-screen`);
        if (targetScreen) {
            targetScreen.classList.add('active');
            
            // Deactivate current screen
            if (this.screens[this.currentScreen] && this.screens[this.currentScreen].deactivate) {
                this.screens[this.currentScreen].deactivate();
            }
            
            this.currentScreen = screenName;
            
            // Activate new screen
            if (this.screens[screenName] && this.screens[screenName].activate) {
                this.screens[screenName].activate();
            }
        }
    }

    updateActiveNavigation() {
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });

        document.querySelectorAll(`[data-screen="${this.currentScreen}"]`).forEach(link => {
            if (link.classList.contains('nav-link')) {
                link.classList.add('active');
            }
        });
    }

    showAlert(message, type = 'info') {
        // Create alert element
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        alert.textContent = message;
        
        // Add close button
        const closeBtn = document.createElement('span');
        closeBtn.innerHTML = '&times;';
        closeBtn.style.float = 'right';
        closeBtn.style.cursor = 'pointer';
        closeBtn.style.marginLeft = '10px';
        closeBtn.onclick = () => alert.remove();
        alert.appendChild(closeBtn);
        
        // Add to alert container or body
        let alertContainer = document.getElementById('alert-container');
        if (!alertContainer) {
            alertContainer = document.createElement('div');
            alertContainer.id = 'alert-container';
            alertContainer.style.position = 'fixed';
            alertContainer.style.top = '100px';
            alertContainer.style.right = '20px';
            alertContainer.style.zIndex = '1000';
            document.body.appendChild(alertContainer);
        }
        
        alertContainer.appendChild(alert);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (alert.parentNode) {
                alert.remove();
            }
        }, 5000);
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Utility methods for screens to use
    getCurrentScreen() {
        return this.currentScreen;
    }

    getScreenController(screenName) {
        return this.screens[screenName];
    }
}

// Global app instance
let app;

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log('Initializing Scam Detection Application...');
    app = new ScamDetectionApp();
    
    // Make app globally accessible for debugging
    window.app = app;
    
    console.log('Application ready!');
});
