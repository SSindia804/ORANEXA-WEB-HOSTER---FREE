const express = require('express');
const fs = require('fs');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const DB_FILE = 'database.json';

// Initialize Database file if not exists
if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ registry: [] }));
}

function getData() { return JSON.parse(fs.readFileSync(DB_FILE)); }
function saveData(data) { fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2)); }

// --- AI CONTENT MODERATOR (Heuristic Engine) ---
const RESTRICTED = ['password', 'cookie', 'localStorage', 'eval(', 'db.json', 'hex(', 'login', 'signin'];
const ADULT = ['gambling', 'bet', 'casino', 'porn', 'hack'];

function analyzeCode(webData) {
    const code = (webData.content.html + webData.content.css + webData.content.js).toLowerCase();
    let risk = 0;
    let flags = [];

    RESTRICTED.forEach(word => {
        if (code.includes(word)) { risk += 20; flags.push(`Security Keyword: ${word}`); }
    });

    ADULT.forEach(word => {
        if (code.includes(word)) { risk += 50; flags.push(`Restricted Content: ${word}`); }
    });

    if (code.includes('<input') && code.includes('password')) {
        risk += 40; flags.push("Potential Phishing Form detected.");
    }

    return { blocked: risk >= 60, score: risk, reasons: flags };
}

// --- API ROUTES ---

// Search Registry
app.get('/api/search', (req, res) => {
    const { q } = req.query;
    const db = getData();
    const results = db.registry.filter(web => 
        web.title.toLowerCase().includes(q.toLowerCase()) || 
        web.url.toLowerCase().includes(q.toLowerCase())
    );
    res.json(results);
});

// Deploy Web (with AI Check)
app.post('/api/deploy', (req, res) => {
    const { user, webData } = req.body;
    const analysis = analyzeCode(webData);

    if (analysis.blocked) {
        return res.status(403).json({ 
            error: "AI BLOCKED: Content violates safety rules.",
            details: analysis.reasons 
        });
    }

    let db = getData();
    const existing = db.registry.find(w => w.url === webData.url && w.author !== user);
    if (existing) return res.status(400).json({ error: "URL ID is already claimed globally." });

    const index = db.registry.findIndex(w => w.url === webData.url);
    if (index > -1) db.registry[index] = webData;
    else db.registry.push(webData);

    saveData(db);
    res.json({ success: true });
});

// Get User's Projects
app.get('/api/user-webs', (req, res) => {
    const { user } = req.query;
    const db = getData();
    res.json(db.registry.filter(w => w.author === user));
});

app.listen(PORT, () => console.log(`Oranexa Server Alpha 1.0 running on Port ${PORT}`));
