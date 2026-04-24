// All password history operations go through the Express/SQLite backend.
// Only SHA-256 hashes are ever sent — plaintext passwords never leave the browser.

const API = "http://localhost:3001/api/history";

export async function savePasswordHash(hash, label = "") {
  const res = await fetch(API, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hash, label }),
  });
  if (res.status === 409) return { alreadyUsed: true };
  if (!res.ok) throw new Error("Failed to save password hash");
  return { alreadyUsed: false };
}

export async function wasPasswordUsed(hash) {
  const res = await fetch(`${API}/check/${hash}`);
  if (!res.ok) return false;
  const { used } = await res.json();
  return used;
}

export async function getPasswordHistory() {
  const res = await fetch(API);
  if (!res.ok) return [];
  return res.json();
}

export async function deleteHistoryEntry(id) {
  await fetch(`${API}/${id}`, { method: "DELETE" });
}

export async function clearHistory() {
  await fetch(API, { method: "DELETE" });
}
