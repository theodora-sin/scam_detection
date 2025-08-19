// static/js/education.js

const educationTips = [
  "Never share personal information via email or phone",
  "Verify URLs before clicking suspicious links",
  "Be skeptical of urgent or time-pressured requests",
  "Be careful about replying to contact numbers or emails",
  "Be cautious of unusual payment methods",
  "Discuss suspicious messages with a trusted person",
  "Never share bank details, names, or financial information on social platforms"
];

const redflags = [
  "Look for suspicious keywords",
  "Requests for immediate payment",
  "Payments via gift cards or cryptocurrency (e.g., Bitcoin)",
  "Poor grammar, spelling, or punctuation in messages"
];

const warningLines = [
  "⚠️ If you suspect this website is a scam:",
  " • Do NOT click the link",
  " • Find someone you trust",
  " • Report to the appropriate authorities"
];

function showEducationScreen() {
  const edu = document.getElementById('educationContainer');
  const main = document.getElementById('mainCanvasContainer');
  if (!edu) return;

  if (main) main.style.display = 'none';
  edu.style.display = 'block';
  edu.innerHTML = '';

  const title = document.createElement('h1');
  title.textContent = 'Scam Education and Prevention';
  edu.appendChild(title);

  const mkSection = (heading, items) => {
    const sec = document.createElement('section');
    const h2 = document.createElement('h2');
    h2.textContent = heading;
    sec.appendChild(h2);

    const ul = document.createElement('ul');
    items.forEach(t => {
      const li = document.createElement('li');
      li.textContent = t;
      li.classList.add('card');
      ul.appendChild(li);
    });
    sec.appendChild(ul);
    edu.appendChild(sec);
  };

  mkSection('Education Tips', educationTips);
  mkSection('Common Red Flags', redflags);

  const warn = document.createElement('div');
  warn.classList.add('warning');
  warn.textContent = warningLines.join('\n');
  edu.appendChild(warn);

  const back = document.createElement('button');
  back.textContent = 'Return to Scanner';
  back.onclick = () => {
    edu.style.display = 'none';
    const main = document.getElementById('mainCanvasContainer');
    if (main) main.style.display = 'block';
    // tell sketch we are back
    if (typeof returnFromEducation === 'function') returnFromEducation();
  };
  edu.appendChild(back);

  // tell sketch we are in education mode
  if (typeof currentScreen !== 'undefined') currentScreen = 'education';
}

