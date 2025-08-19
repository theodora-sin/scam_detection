// static/js/mainScreen.js

function drawMainScreen(scanFn, setRiskFn, ensureUiFn) {
  setGradientBackground(color(100, 150, 255), color(50, 100, 200));

  fill(255);
  textAlign(CENTER);
  textSize(30);
  text('Welcome to Scam Detection', width / 2, 80);

  textSize(18);
  text('Enter a website URL to check its risk level', width / 2, 140);

  // Ensure input + button are visible
  ensureUiFn();

  // Wire scan
  submitButton.mousePressed(async () => {
    try {
      // disable button during scan
      submitButton.attribute('disabled', 'true');
      const url = inputBox.value().trim();
      await scanFn(url); // calls backend, sets current screen accordingly
    } catch (e) {
      alert(e.message || 'Scan failed');
    } finally {
      submitButton.removeAttribute('disabled');
    }
  });

  // Education quick button
  if (!eduButton) {
    eduButton = createButton('Education');
    styleButton(eduButton);
    eduButton.size(120, 36);
    eduButton.position(width / 2 - 60, 330);
    eduButton.mousePressed(() => {
      // hide inputs on education
      if (inputBox) { inputBox.remove(); inputBox = null; }
      if (submitButton) { submitButton.remove(); submitButton = null; }
      currentScreen = 'education';
      showEducationScreen();
    });
  }
}

function drawRiskScreen(kind, score, onReturn) {
  const palette = {
    extreme: [color(250, 9, 9),   color(236, 107, 92)],
    high:    [color(220, 53, 69), color(231, 76, 60)],
    medium:  [color(253, 126, 20), color(243, 156, 18)],
    low:     [color(255, 193, 7), color(241, 196, 15)],
    minimal: [color(25, 135, 84), color(39, 174, 96)],
    unknown: [color(108, 117, 125), color(149, 165, 166)]
  };

  const [c1, c2] = palette[kind] || palette.unknown;
  setGradientBackground(c1, c2);

  const titleMap = {
    extreme: 'EXTREME RISK',
    high:    'HIGH RISK',
    medium:  'MEDIUM RISK',
    low:     'LOW RISK',
    minimal: 'MINIMAL RISK',
    unknown: 'RISK UNKNOWN'
  };

  const darkText = (kind === 'low'); // better contrast
  fill(darkText ? 0 : 255);
  textAlign(CENTER);
  textSize(30);

  if (typeof score === 'number') {
    text(`Total Score: ${score}`, width / 2, height / 2 - 180);
  }
  text(titleMap[kind] || 'RISK', width / 2, height / 2 - 120);

  if (!returnButton) {
    returnButton = createButton('Return to Main');
    returnButton.position(width / 2 - 80, height / 2 + 10);
    returnButton.size(160, 44);
    styleButton(returnButton);
    returnButton.mousePressed(() => {
      returnButton.remove();
      returnButton = null;
      suspicious_score = 0;
      onReturn();
    });
  }
}
