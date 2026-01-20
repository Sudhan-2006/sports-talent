// server.js — ES module (Node 14+ / Node 22+)
import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import fs from "fs";
import path from "path";
import sqlite3pkg from "sqlite3";
import { fileURLToPath } from "url";

// Fix __dirname in ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const { verbose } = sqlite3pkg;
const sqlite3 = verbose();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "replace_with_a_strong_secret";

// --- Optional: path to the guide image you uploaded earlier ---
// Developer note: you uploaded a file earlier. Path in the conversation:
const GUIDE_IMAGE_PATH = "/mnt/data/A_step-by-step_guide_in_a_digital_graphic_displays.png";
// You can reference / expose that path in the frontend or copy the file into frontend images folder.

// --- Setup DB (SQLite) ---
const dbFile = path.join(__dirname, "db.sqlite");
const db = new sqlite3.Database(dbFile);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT 'athlete',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    filename TEXT,
    originalname TEXT,
    filesize INTEGER,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'pending',
    metadata TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  // Eligibility / training table
  db.run(`CREATE TABLE IF NOT EXISTS eligibilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    sport TEXT,
    age INTEGER,
    gender TEXT,
    height REAL,
    weight REAL,
    experience TEXT,
    aadhaar TEXT,
    aadhaar_verified INTEGER DEFAULT 0,
    eligible INTEGER DEFAULT 0,
    notes TEXT,
    training_plan_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

// --- Middleware ---
app.use(cors());
app.use(express.json());
// serve uploads folder
const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
app.use("/uploads", express.static(UPLOAD_DIR));

// (Optional) serve frontend if you keep it in a folder next to backend (uncomment and set correct folder):
// const FRONTEND_DIR = path.join(__dirname, '..', 'sports-frotend');
// if (fs.existsSync(FRONTEND_DIR)) app.use(express.static(FRONTEND_DIR));

// Multer config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const name = `${Date.now()}_${file.originalname.replace(/\s+/g, "_")}`;
    cb(null, name);
  },
});
const upload = multer({ storage, limits: { fileSize: 2000 * 1024 * 1024 } }); // ~2GB

// --- Helpers ---
function generateToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
}
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "Missing authorization header" });
  const token = auth.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Invalid authorization header" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// --- Eligibility rules + training generator ---
const TRAINING_DEFAULT_DAYS = 30;

const eligibilityRules = {
  "Running": [
    { minAge: 12, maxAge: 30, requirement: { type: "run_1km_s", maxSeconds: 420, description: "Run 1 km under 7 minutes" } }
  ],
  "Long Jump": [
    { minAge: 12, maxAge: 28, requirement: { type: "distance_m", minMeters: 3.0, description: "Long jump at least 3.0 meters" } }
  ],
  "High Jump": [
    { minAge: 12, maxAge: 25, requirement: { type: "height_m", minMeters: 1.10, description: "High jump at least 1.10 meters" } }
  ],
  "Javelin Throw": [
    { minAge: 15, maxAge: 30, requirement: { type: "distance_m", minMeters: 20, description: "Throw at least 20 meters" } }
  ],
  "Shot Put": [
    { minAge: 15, maxAge: 35, requirement: { type: "distance_m", minMeters: 5, description: "Put at least 5 meters" } }
  ],
  "Swimming": [
    { minAge: 10, maxAge: 25, requirement: { type: "swim_50m_s", maxSeconds: 60, description: "Swim 50m non-stop" } }
  ],
  "Relay Race": [
    { minAge: 12, maxAge: 30, requirement: { type: "sprint_100m_s", maxSeconds: 16, description: "Run 100m under 16 seconds" } }
  ],
};

// training plan generator (simple deterministic generator)
function generateTrainingPlan(sport, days = TRAINING_DEFAULT_DAYS, level = "Beginner") {
  const plan = [];
  for (let d = 1; d <= days; d++) {
    let task = "";
    if (sport === "Long Jump") {
      if (d % 7 === 0) task = "Rest + mobility + light stretching";
      else if (d % 3 === 0) task = "Speed work: 6 x 30m sprints + recovery";
      else if (d % 2 === 0) task = "Bounding drills & plyometrics: 3 sets";
      else task = "Technique: approach run + takeoff drills, 6 practice jumps";
    } else if (sport === "Running") {
      if (d % 7 === 0) task = "Rest or easy recovery jog (20-30 min)";
      else if (d % 3 === 0) task = "Interval training: 6 x 200m with 2 min rest";
      else task = "Tempo run: 20-30 minutes steady pace + mobility";
    } else if (sport === "High Jump") {
      if (d % 7 === 0) task = "Rest + flexibility work";
      else if (d % 3 === 0) task = "Approach and takeoff drills + mat practice";
      else task = "Strength: squat variants + core (moderate)";
    } else if (sport === "Swimming") {
      if (d % 7 === 0) task = "Technique and easy swim (focus on stroke)";
      else task = "Endurance sets: 10 x 50m at controlled pace";
    } else if (sport === "Javelin Throw") {
      if (d % 7 === 0) task = "Recovery & shoulder mobility";
      else if (d % 3 === 0) task = "Throw technique work: 10-15 throws (light)";
      else task = "Strength & core + medicine ball throws";
    } else if (sport === "Shot Put") {
      if (d % 7 === 0) task = "Recovery & mobility";
      else if (d % 3 === 0) task = "Technique drills: glide/rotation without heavy load";
      else task = "Strength training: throws + core";
    } else {
      task = "General fitness, mobility, and sport-specific drills";
    }

    // tweak by level
    if (level === "Advanced") task += " (increase sets/intensity)";
    else if (level === "Intermediate") task += " (moderate intensity)";
    plan.push({ day: d, task });
  }
  return plan;
}

// Verhoeff algorithm for Aadhaar checksum validation
const verhoeff_d = [
  [0,1,2,3,4,5,6,7,8,9],
  [1,2,3,4,0,6,7,8,9,5],
  [2,3,4,0,1,7,8,9,5,6],
  [3,4,0,1,2,8,9,5,6,7],
  [4,0,1,2,3,9,5,6,7,8],
  [5,9,8,7,6,0,4,3,2,1],
  [6,5,9,8,7,1,0,4,3,2],
  [7,6,5,9,8,2,1,0,4,3],
  [8,7,6,5,9,3,2,1,0,4],
  [9,8,7,6,5,4,3,2,1,0]
];
const verhoeff_p = [
  [0,1,2,3,4,5,6,7,8,9],
  [1,5,7,6,2,8,3,0,9,4],
  [5,8,0,3,7,9,6,1,4,2],
  [8,9,1,6,0,4,3,5,2,7],
  [9,4,5,3,1,2,6,8,7,0],
  [4,2,8,6,5,7,3,9,0,1],
  [2,7,9,3,8,0,6,4,1,5],
  [7,0,4,6,9,1,3,2,5,8]
];
function verhoeffCheck(numStr) {
  if (!/^\d+$/.test(numStr)) return false;
  let c = 0;
  const arr = numStr.split('').map(Number).reverse();
  for (let i = 0; i < arr.length; i++) {
    c = verhoeff_d[c][verhoeff_p[i % 8][arr[i]]];
  }
  return c === 0;
}

// --- Routes ---
// Root / health
app.get("/", (req, res) => res.json({ ok: true, msg: "Sports backend running" }));

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { name = "", email = "", password = "", role = "athlete" } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });
    const hash = await bcrypt.hash(password, 10);
    db.run(
      `INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)`,
      [name, email.toLowerCase(), hash, role],
      function (err) {
        if (err) {
          if (err.message && err.message.includes("UNIQUE")) return res.status(400).json({ error: "Email already in use" });
          return res.status(500).json({ error: "DB error", details: err.message });
        }
        const user = { id: this.lastID, name, email, role };
        const token = generateToken(user);
        res.json({ user, token });
      }
    );
  } catch (err) {
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// Login
app.post("/api/login", (req, res) => {
  const { email = "", password = "" } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });
  db.get(
    `SELECT id, name, email, password_hash, role FROM users WHERE email = ?`,
    [email.toLowerCase()],
    async (err, row) => {
      if (err) return res.status(500).json({ error: "DB error" });
      if (!row) return res.status(401).json({ error: "Invalid credentials" });
      const ok = await bcrypt.compare(password, row.password_hash);
      if (!ok) return res.status(401).json({ error: "Invalid credentials" });
      const user = { id: row.id, name: row.name, email: row.email, role: row.role };
      const token = generateToken(user);
      res.json({ user, token });
    }
  );
});

// Profile
app.get("/api/profile", authMiddleware, (req, res) => {
  db.get(`SELECT id, name, email, role, created_at FROM users WHERE id = ?`, [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json({ profile: row });
  });
});

// Upload video
app.post("/api/upload", authMiddleware, upload.single("video"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  const { filename, originalname, size } = req.file;
  const userId = req.user.id;
  const metadata = JSON.stringify({ uploadedBy: userId, notes: req.body.notes || "" });
  db.run(
    `INSERT INTO videos (user_id, filename, originalname, filesize, metadata) VALUES (?, ?, ?, ?, ?)`,
    [userId, filename, originalname, size, metadata],
    function (err) {
      if (err) return res.status(500).json({ error: "DB error", details: err.message });
      const videoId = this.lastID;
      // Demo analysis
      const demoReport = {
        videoId,
        scores: {
          speed: Math.round(Math.random() * 100),
          agility: Math.round(Math.random() * 100),
          technique: Math.round(Math.random() * 100)
        },
        summary: "Demo analysis generated. Replace with real AI model later."
      };
      res.json({ ok: true, video: { id: videoId, filename, originalname }, report: demoReport });
    }
  );
});

// Save user sports preferences (simple file-based demo)
app.post("/api/preferences", authMiddleware, (req, res) => {
  const { sports } = req.body;
  if (!sports || !Array.isArray(sports)) return res.status(400).json({ error: "Invalid sports data" });

  const preferencesFile = path.join(__dirname, "user_preferences.json");
  const allPrefs = fs.existsSync(preferencesFile) ? JSON.parse(fs.readFileSync(preferencesFile, "utf8")) : {};
  allPrefs[req.user.id] = sports;
  fs.writeFileSync(preferencesFile, JSON.stringify(allPrefs, null, 2));
  res.json({ ok: true, saved: sports });
});

// GET eligibility rules (public)
app.get("/api/eligibility-rules", (req, res) => {
  res.json({ ok: true, rules: eligibilityRules });
});

// POST calc-eligibility (protected) — evaluate & save, returns training plan
app.post("/api/calc-eligibility", authMiddleware, (req, res) => {
  try {
    const userId = req.user.id;
    const { sport, age, gender, height, weight, experience = "Beginner", aadhaar } = req.body;
    if (!sport || typeof age === "undefined") return res.status(400).json({ error: "Missing sport or age" });

    // find rule for sport and age
    const rules = eligibilityRules[sport] || [];
    const matched = rules.find(r => age >= r.minAge && age <= r.maxAge);
    let eligible = true;
    let notes = "";

    if (matched) {
      const reqt = matched.requirement;
      if (reqt.type === "distance_m" && typeof reqt.minMeters === "number") notes = `Target: min ${reqt.minMeters} m`;
      else if (reqt.type === "height_m") notes = `Target: min ${reqt.minMeters} m (height)`;
      else if (reqt.type.indexOf("time") >= 0) notes = `Target: max ${reqt.maxSeconds || reqt.maxSeconds} s`;
      else notes = reqt.description || JSON.stringify(reqt);
    } else {
      notes = "No exact rule for this age group; follow general training plan.";
    }

    // small heuristic checks (example)
    if (sport === "High Jump" && height && height < 1.1) {
      eligible = false;
      notes += " — Height below recommended for high jump (you can still train).";
    }
    if (sport === "Running" && typeof age === "number" && age < 12) {
      eligible = false;
      notes += " — Minimum age for running events in this platform is 12.";
    }

    // Aadhaar basic validation (format + checksum)
    let aadhaarVerified = 0;
    if (aadhaar && typeof aadhaar === "string") {
      const cleaned = aadhaar.replace(/\s+/g, "");
      if (/^\d{12}$/.test(cleaned) && verhoeffCheck(cleaned)) aadhaarVerified = 1;
    }

    // generate plan
    const plan = generateTrainingPlan(sport, TRAINING_DEFAULT_DAYS, experience);

    // save row to DB
    const stmt = db.prepare(`INSERT INTO eligibilities (user_id, sport, age, gender, height, weight, experience, aadhaar, aadhaar_verified, eligible, notes, training_plan_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    stmt.run(userId, sport, age, gender, height || null, weight || null, experience, aadhaar || null, aadhaarVerified, eligible ? 1 : 0, notes, JSON.stringify(plan), function (err) {
      if (err) return res.status(500).json({ error: "DB error", details: err.message });
      res.json({ ok: true, eligibility: { id: this.lastID, eligible, notes }, trainingPlan: plan });
    });
  } catch (err) {
    res.status(500).json({ error: "Server error", details: err.message });
  }
});

// GET my eligibilities (protected)
app.get("/api/my-eligibilities", authMiddleware, (req, res) => {
  db.all(`SELECT id, sport, age, gender, height, weight, experience, aadhaar, aadhaar_verified, eligible, notes, training_plan_json, created_at FROM eligibilities WHERE user_id = ? ORDER BY created_at DESC`, [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    const parsed = rows.map(r => ({ ...r, training_plan: r.training_plan_json ? JSON.parse(r.training_plan_json) : [] }));
    res.json({ ok: true, eligibilities: parsed });
  });
});

// Simple endpoint to check aadhaar only (public) - format & checksum
app.post("/api/verify-aadhaar", (req, res) => {
  const { aadhaar } = req.body;
  if (!aadhaar || typeof aadhaar !== "string") return res.status(400).json({ ok: false, reason: "Invalid aadhaar" });
  const num = aadhaar.replace(/\s+/g, "");
  if (!/^\d{12}$/.test(num)) return res.json({ ok: false, reason: "Aadhaar must be 12 digits" });
  const valid = verhoeffCheck(num);
  if (!valid) return res.json({ ok: false, reason: "Verhoeff checksum failed" });
  return res.json({ ok: true, reason: "Aadhaar format and checksum valid (not government-verified)" });
});

// Export the guide image path (so frontend can display if needed)
app.get("/api/guide-image", (req, res) => {
  // If you want to actually serve the image from this server, copy the file into your frontend images folder
  // or move the file into uploads/ and serve it. For now we return the local path for your use.
  res.json({ ok: true, path: GUIDE_IMAGE_PATH });
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log("Endpoints available: /api/register /api/login /api/profile /api/upload /api/preferences /api/eligibility-rules /api/calc-eligibility /api/my-eligibilities");
});
