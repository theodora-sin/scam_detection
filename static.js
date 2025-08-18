// static/js/app.js

// Global UI refs created by p5 DOM helpers
let inputBox, submitButton, returnButton, eduButton;
let suspicious_score = 0;
let currentScreen = 'start';  // 'start' | 'main' | risk ids: 'extreme','high','medium','low','minimal','unknown'

// p5 setup/draw – the only place where these exist
function setup() {
  const c = createCanvas(800, 600);
  // Mount the canvas inside the container div
  const host = document.getElementById('mainCanvasContainer');
  if (host) c.parent(host);

  // Topbar buttons (DOM) wiring
  const btnStart = document.getElementById('btnStart');
  const btnMain = document.getElementById('btnMain');
  const btnEdu  = document.getElementById('btnEducation');

  if (btnStart) btnStart.onclick = () => switchTo('start');
  if (btnMain)  btnMain.onclick  = () => switchTo('main');
  if (btnEdu)   btnEdu.onclick   = showEducationScreen; // defined in education.js
}

function draw() {
  clear();

  // Hide/show proper container when on education
  const mainContainer = document.getElementById('mainCanvasContainer');
  const eduContainer  = document.getElementById('educationContainer');
  if (currentScreen === 'education') {
    if (mainContainer) mainContainer.style.display = 'none';
    if (eduContainer)  eduContainer.style.display  = 'block';
    return; // no canvas drawing when in education
  } else {
    if (eduContainer)  eduContainer.style.display  = 'none';
    if (mainContainer) mainContainer.style.display = 'block';
  }

  switch (currentScreen) {
    case 'start':
      drawStartScreen(switchToMain);      // from startScreen.js
      break;
    case 'main':
      drawMainScreen(analyzeWebsiteFetch, setRiskScreen, ensureMainInputs); // from mainScreen.js
      break;
    case 'extreme':
    case 'high':
    case 'medium':
    case 'low':
    case 'minimal':
    case 'unknown':
      drawRiskScreen(currentScreen, suspicious_score, switchToMain); // from mainScreen.js
      break;
  }
}

// -------- Navigation helpers --------
function switchTo(screen) {
  // Clean UI (remove stray buttons)
  if (returnButton) { returnButton.remove(); returnButton = null; }
  if (eduButton)    { eduButton.remove();    eduButton    = null; }

  // If leaving main, hide inputs
  if (screen !== 'main') {
    if (inputBox)     { inputBox.remove();     inputBox = null; }
    if (submitButton) { submitButton.remove(); submitButton = null; }
  }
  currentScreen = screen;
}

function switchToMain()  { switchTo('main'); }
function switchToStart() { switchTo('start'); }

// Called by Education "Return" button
function returnFromEducation() {
  currentScreen = 'main';
}

// ---------- Main screen actions ----------
async function analyzeWebsiteFetch(url) {
  // Add protocol if missing
  let cleaned = (url || '').trim();
  if (!cleaned) throw new Error('Please enter a URL');
  if (!/^https?:\/\//i.test(cleaned)) cleaned = 'https://' + cleaned;

  const res = await fetch('/scan_url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: cleaned })
  });
  const data = await res.json();

  if (!res.ok || data.status === 'error') {
    throw new Error(data.message || 'Scan failed');
  }

  const risk = data.risk_assessment || {};
  suspicious_score = typeof risk.score === 'number' ? risk.score : 50;

  // Decide risk band
  if (suspicious_score >= 80) currentScreen = 'extreme';
  else if (suspicious_score >= 60) currentScreen = 'high';
  else if (suspicious_score >= 40) currentScreen = 'medium';
  else if (suspicious_score >= 20) currentScreen = 'low';
  else currentScreen = 'minimal';

  return data;
}

// For main screen to switch after local random (fallback) – not used when backend available
function setRiskScreen(score) {
  suspicious_score = score;
  if (score >= 80) currentScreen = 'extreme';
  else if (score >= 60) currentScreen = 'high';
  else if (score >= 40) currentScreen = 'medium';
  else if (score >= 20) currentScreen = 'low';
  else currentScreen = 'minimal';
}

// Ensure input elements exist/visible (used by main screen drawing)
function ensureMainInputs() {
  if (!inputBox) {
    inputBox = createInput();
    inputBox.size(300, 35);
    inputBox.attribute('placeholder', 'Enter website URL');
    inputBox.position(width / 2 - 150, 220);
  }
  if (!submitButton) {
    submitButton = createButton('Scan URL');
    submitButton.size(120, 40);
    styleButton(submitButton);
    submitButton.position(width / 2 - 60, 270);
  }
}
