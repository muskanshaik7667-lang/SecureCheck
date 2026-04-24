const express = require("express");
const cors = require("cors");
const db = require("./database");

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());
app.use(express.static(require("path").join(__dirname, "..")));

// Check if a hash was previously used
app.get("/api/history/check/:hash", (req, res) => {
  const used = db.exists(req.params.hash);
  res.json({ used });
});

// Save a new password hash
app.post("/api/history", (req, res) => {
  const { hash, label } = req.body;
  if (!hash) return res.status(400).json({ error: "hash is required" });

  const saved = db.save(hash, label || "");
  if (!saved) {
    return res.status(409).json({ error: "Password already in history" });
  }
  res.json({ success: true });
});

// Get all history entries (no hashes exposed)
app.get("/api/history", (_req, res) => {
  res.json(db.all());
});

// Delete a single entry
app.delete("/api/history/:id", (req, res) => {
  db.remove(Number(req.params.id));
  res.json({ success: true });
});

// Clear all history
app.delete("/api/history", (_req, res) => {
  db.clear();
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`Password Analyzer running at http://localhost:${PORT}`);
});
