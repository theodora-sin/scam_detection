const express = require("express");
const { URL } = require("url");

const app = express();
app.use(express.json());

const SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "banking", "update"];
const SUSPICIOUS_TLDS = [".ru", ".tk", ".cn"];

// Basic scam scan function
function basicScan(url) {
    let score = 0;
    let reasons = [];

    try {
        let parsed = new URL(url);

        // Check protocol
        if (!url.startsWith("https://")) {
            score += 20;
            reasons.push("URL is not HTTPS secured");
        }

        // Check length
        if (url.length > 100) {
            score += 15;
            reasons.push("URL is unusually long");
        }

        // Check suspicious TLDs
        SUSPICIOUS_TLDS.forEach(tld => {
            if (parsed.hostname.endsWith(tld)) {
                score += 25;
                reasons.push(`Suspicious domain ending (${tld})`);
            }
        });

        // Check for suspicious keywords
        SUSPICIOUS_KEYWORDS.forEach(keyword => {
            if (url.toLowerCase().includes(keyword)) {
                score += 20;
                reasons.push(`Contains suspicious keyword: ${keyword}`);
            }
        });

        // Cap score at 100
        score = Math.min(score, 100);

        // Risk level mapping
        let level, color;
        if (score >= 80) {
            level = "VERY HIGH"; color = "danger";
        } else if (score >= 60) {
            level = "HIGH"; color = "danger";
        } else if (score >= 40) {
            level = "MEDIUM"; color = "warning";
        } else if (score >= 20) {
            level = "LOW"; color = "info";
        } else {
            level = "MINIMAL"; color = "success";
        }

        return {
            status: "ok",
            url: url,
            risk_assessment: {
                score: score,
                level: level,
                color: color,
                factors: reasons.length > 0 ? reasons : ["No obvious scam signs detected"]
            },
            timestamp_backend: new Date().toISOString()
        };

    } catch (error) {
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
}

// Routes
app.get("/", (req, res) => {
    res.sendFile(__dirname + "/index.html");
});

app.post("/scan_url", (req, res) => {
    try {
        let url = (req.body.url || "").trim();
        if (!url) {
            return res.status(400).json({ status: "error", message: "No URL provided" });
        }

        // Default to https:// if missing
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url;
        }

        const result = basicScan(url);
        res.json(result);

    } catch (e) {
        res.status(500).json({
            status: "error",
            message: e.toString(),
            risk_assessment: {
                score: 50,
                level: "UNKNOWN",
                color: "secondary",
                factors: ["Analysis failed due to error"]
            }
        });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

