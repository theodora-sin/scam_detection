const express = require("express");
const path = require("path");
const { URL } = require("url");

const app = express();

// --- middleware ---
app.use(express.json());

// serve index.html (and any other static assets if you add a /static directory)
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// --- constants copied from your Python logic ---
const SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "banking", "update"];
const SUSPICIOUS_TLDS = [".ru", ".tk", ".cn"];

// --- core scan function (same scoring you specified) ---
function basicScan(url) {
  let score = 0;
  const reasons = [];

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
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

  if (!url.startsWith("https://")) {
    score += 20;
    reasons.push("URL is not HTTPS secured");
  }

  if (url.length > 100) {
    score += 15;
    reasons.push("URL is unusually long");
  }

  SUSPICIOUS_TLDS.forEach(tld => {
    if (parsed.hostname.endsWith(tld)) {
      score += 25;
      reasons.push(`Suspicious domain ending (${tld})`);
    }
  });

  SUSPICIOUS_KEYWORDS.forEach(k => {
    if (url.toLowerCase().includes(k)) {
      score += 20;
      reasons.push(`Contains suspicious keyword: ${k}`);
    }
  });

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
    risk_assessment: {
      score,
      level,
      color,
      factors: reasons.length ? reasons : ["No obvious scam signs detected"]
    },
    timestamp_backend: new Date().toISOString()
  };
}

// --- routes ---
app.post("/scan_url", (req, res) => {
  let url = (req.body?.url || "").trim();

  if (!url) {
    return res.status(400).json({ status: "error", message: "No URL provided" });
  }

  if (!/^https?:\/\//i.test(url)) {
    url = "https://" + url; // default to https if missing
  }

  const result = basicScan(url);
  res.json(result);
});

// return clean JSON for wrong methods instead of an HTML error (prevents the "<html>… not valid JSON" error)
app.all("/scan_url", (req, res, next) => {
  if (req.method !== "POST") {
    return res.status(405).json({
      status: "error",
      message: "Method Not Allowed. Use POST."
    });
  }
  next();
});

// --- start ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(` Scam Detection backend running at http://localhost:${PORT}`);
});
