// backend/routes.js
const { URL } = require("url");

// Scam detection constants
const SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "banking", "update"];
const SUSPICIOUS_TLDS = [".ru", ".tk", ".cn"];

// Core scan function
function basicScan(url) {
  let score = 0;
  const reasons = [];
  let parsed;

  try { parsed = new URL(url); }
  catch {
    return {
      status: "error",
      message: "Invalid URL format",
      risk_assessment: {
        score: 50,
        level: "UNKNOWN",
        color: "secondary",
        factors: ["Analysis failed due to error"]
      },
      timestamp_backend: new Date().toISOString()
    };
  }

  if (!url.startsWith("https://")) { score += 20; reasons.push("URL is not HTTPS"); }
  if (url.length > 100) { score += 15; reasons.push("URL is unusually long"); }
  SUSPICIOUS_TLDS.forEach(tld => { if (parsed.hostname.endsWith(tld)) { score += 25; reasons.push(`Suspicious TLD: ${tld}`); }});
  SUSPICIOUS_KEYWORDS.forEach(k => { if (url.toLowerCase().includes(k)) { score += 20; reasons.push(`Contains keyword: ${k}`); }});

  score = Math.min(score, 100);

  let level, color;
  if (score >= 80) { level = "VERY HIGH"; color = "danger"; }
  else if (score >= 60) { level = "HIGH"; color = "danger"; }
  else if (score >= 40) { level = "MEDIUM"; color = "warning"; }
  else if (score >= 20) { level = "LOW"; color = "info"; }
  else { level = "MINIMAL"; color = "success"; }

  return {
    status: "ok",
    url,
    risk_assessment: { score, level, color, factors: reasons.length ? reasons : ["No obvious scam signs detected"] },
    timestamp_backend: new Date().toISOString()
  };
}

// Export a function to initialize routes
function initRoutes(app) {
  app.post("/scan_url", (req, res) => {
    let url = (req.body?.url || "").trim();
    if (!url) return res.status(400).json({ status: "error", message: "No URL provided" });
    if (!/^https?:\/\//i.test(url)) url = "https://" + url;
    res.json(basicScan(url));
  });

  // Handle non-POST requests
  app.all("/scan_url", (req, res, next) => {
    if (req.method !== "POST") return res.status(405).json({ status: "error", message: "Method Not Allowed" });
    next();
  });
}

module.exports = { initRoutes };

