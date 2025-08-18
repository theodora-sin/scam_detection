// static/js/startScreen.js

function drawStartScreen(onContinue) {
  // Background gradient
  setGradientBackground(color(102, 126, 234), color(118, 75, 162));

  fill(255);
  textAlign(CENTER);
  textSize(36);
  text('🛡️ Advanced Scam Detection', width / 2, 120);

  textSize(18);
  text('Check a website URL for potential scam signals', width / 2, 160);

  // Big "Get Started" button (p5 DOM)
  if (!returnButton) {
    returnButton = createButton('Get Started');
    returnButton.size(160, 50);
    styleButton(returnButton);
    returnButton.position(width / 2 - 80, 220);
    returnButton.mousePressed(() => {
      returnButton.remove();
      returnButton = null;
      onContinue();
    });
  }

  // Optional: quick link to Education
  if (!eduButton) {
    eduButton = createButton('Open Education');
    eduButton.size(160, 40);
    styleButton(eduButton);
    eduButton.position(width / 2 - 80, 290);
    eduButton.mousePressed(() => {
      if (returnButton) { returnButton.remove(); returnButton = null; }
      currentScreen = 'education';
      showEducationScreen(); // defined in education.js (DOM-only)
    });
  }
}

// Shared helper (available in global scope via p5)
function setGradientBackground(c1, c2) {
  noFill();
  for (let y = 0; y < height; y++) {
    const inter = map(y, 0, height, 0, 1);
    const c = lerpColor(c1, c2, inter);
    stroke(c);
    line(0, y, width, y);
  }
}

function styleButton(btn) {
  btn.style('background-color', '#007bff');
  btn.style('color', '#fff');
  btn.style('border', 'none');
  btn.style('border-radius', '6px');
  btn.style('font-size', '16px');
  btn.style('box-shadow', '0 2px 6px rgba(0,0,0,0.2)');
}
