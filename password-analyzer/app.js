import { analyzePassword, checkBreached, generateStrongPassword, hashPassword } from "./crypto-utils.js";
import { savePasswordHash, wasPasswordUsed, getPasswordHistory, deleteHistoryEntry, clearHistory } from "./db.js";

const input       = document.getElementById("password-input");
const toggleBtn   = document.getElementById("toggle-visibility");
const strengthBar = document.getElementById("strength-bar");
const strengthLabel = document.getElementById("strength-label");
const entropyEl   = document.getElementById("entropy");
const feedbackList = document.getElementById("feedback-list");
const breachStatus = document.getElementById("breach-status");
const reuseStatus  = document.getElementById("reuse-status");
const suggestionsEl = document.getElementById("suggestions");
const saveBtn      = document.getElementById("save-btn");
const clearBtn     = document.getElementById("clear-history");
const historyTable = document.getElementById("history-table");
const historyBody  = document.getElementById("history-body");
const historyCount = document.getElementById("history-count");

const STRENGTH_LABELS = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong", "Excellent"];
const STRENGTH_COLORS = ["#e74c3c","#e74c3c","#e67e22","#f1c40f","#2ecc71","#27ae60","#1abc9c"];

let debounceTimer;
let currentHash = null;

input.addEventListener("input", () => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => evaluate(input.value), 300);
});

toggleBtn.addEventListener("click", () => {
  const isPassword = input.type === "password";
  input.type = isPassword ? "text" : "password";
  toggleBtn.textContent = isPassword ? "🙈" : "👁️";
});

saveBtn.addEventListener("click", async () => {
  if (!currentHash || !input.value) return;
  const label = input.value.slice(0, 3) + "*".repeat(Math.max(0, input.value.length - 3));
  const result = await savePasswordHash(currentHash, label);
  if (result.alreadyUsed) {
    reuseStatus.textContent = "⚠️ Already in history — not saved again";
    reuseStatus.className = "status danger";
  } else {
    reuseStatus.textContent = "✅ Saved to history";
    reuseStatus.className = "status safe";
    await refreshHistory();
  }
});

clearBtn.addEventListener("click", async () => {
  await clearHistory();
  await refreshHistory();
  reuseStatus.textContent = "";
});

document.getElementById("generate-btn").addEventListener("click", () => {
  const strong = generateStrongPassword();
  input.value = strong;
  input.type = "text";
  toggleBtn.textContent = "🙈";
  evaluate(strong);
});

async function evaluate(password) {
  if (!password) { resetUI(); return; }

  const { score, feedback, entropy } = analyzePassword(password);
  currentHash = await hashPassword(password);

  // Strength bar
  const pct = Math.round((score / 7) * 100);
  strengthBar.style.width = pct + "%";
  strengthBar.style.background = STRENGTH_COLORS[score] || STRENGTH_COLORS[0];
  strengthLabel.textContent = STRENGTH_LABELS[score] || "Very Weak";
  strengthLabel.style.color = STRENGTH_COLORS[score] || STRENGTH_COLORS[0];

  entropyEl.textContent = `Entropy: ~${entropy} bits`;

  feedbackList.innerHTML = feedback.length
    ? feedback.map((f) => `<li>⚠️ ${f}</li>`).join("")
    : "<li>✅ Looks solid!</li>";

  // Suggestions
  suggestionsEl.innerHTML = "";
  if (score < 5) {
    const suggestions = Array.from({ length: 3 }, () => generateStrongPassword());
    suggestionsEl.innerHTML =
      "<p>Try one of these stronger alternatives:</p>" +
      suggestions.map((s) => `<code class="suggestion" title="Click to use">${s}</code>`).join("");
    suggestionsEl.querySelectorAll(".suggestion").forEach((el) => {
      el.addEventListener("click", () => {
        input.value = el.textContent;
        input.type = "text";
        evaluate(el.textContent);
      });
    });
  }

  // Breach check (non-blocking)
  breachStatus.textContent = "Checking breach databases...";
  breachStatus.className = "status";
  checkBreached(password).then((breached) => {
    breachStatus.textContent = breached
      ? "⚠️ Found in known data breaches!"
      : "✅ Not found in known breaches";
    breachStatus.className = breached ? "status danger" : "status safe";
  });

  // Reuse check against SQLite DB
  const reused = await wasPasswordUsed(currentHash);
  reuseStatus.textContent = reused
    ? "⚠️ You've used this password before"
    : "✅ Not in your password history";
  reuseStatus.className = reused ? "status danger" : "status safe";
}

async function refreshHistory() {
  const history = await getPasswordHistory();
  historyCount.textContent = `${history.length} password(s) stored`;

  if (history.length === 0) {
    historyTable.style.display = "none";
    return;
  }

  historyTable.style.display = "table";
  historyBody.innerHTML = history.map((row) => `
    <tr>
      <td>${row.label || "(no label)"}</td>
      <td>${new Date(row.used_at).toLocaleString()}</td>
      <td>
        <button class="delete-btn" data-id="${row.id}" title="Remove">🗑️</button>
      </td>
    </tr>
  `).join("");

  historyBody.querySelectorAll(".delete-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await deleteHistoryEntry(btn.dataset.id);
      await refreshHistory();
    });
  });
}

function resetUI() {
  strengthBar.style.width = "0%";
  strengthLabel.textContent = "";
  entropyEl.textContent = "";
  feedbackList.innerHTML = "";
  breachStatus.textContent = "";
  reuseStatus.textContent = "";
  suggestionsEl.innerHTML = "";
  currentHash = null;
}

refreshHistory();
