const Database = require("better-sqlite3");
const path = require("path");

const db = new Database(path.join(__dirname, "passwords.db"));

// Create table on first run
db.exec(`
  CREATE TABLE IF NOT EXISTS password_history (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    hash    TEXT    NOT NULL UNIQUE,
    label   TEXT,
    used_at INTEGER NOT NULL
  )
`);

module.exports = {
  // Save a hashed password; returns false if it already exists
  save(hash, label = "") {
    try {
      db.prepare(
        "INSERT INTO password_history (hash, label, used_at) VALUES (?, ?, ?)"
      ).run(hash, label, Date.now());
      return true;
    } catch (e) {
      if (e.code === "SQLITE_CONSTRAINT_UNIQUE") return false; // already used
      throw e;
    }
  },

  // Check if a hash exists
  exists(hash) {
    return !!db.prepare("SELECT 1 FROM password_history WHERE hash = ?").get(hash);
  },

  // Return all records (hashes only, never plaintext)
  all() {
    return db.prepare(
      "SELECT id, label, used_at FROM password_history ORDER BY used_at DESC"
    ).all();
  },

  // Delete a single entry by id
  remove(id) {
    db.prepare("DELETE FROM password_history WHERE id = ?").run(id);
  },

  // Wipe everything
  clear() {
    db.prepare("DELETE FROM password_history").run();
  },
};
