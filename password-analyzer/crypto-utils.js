// Hashes a password using SHA-256 via Web Crypto API
export async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Checks HaveIBeenPwned API using k-anonymity (only sends first 5 chars of hash)
export async function checkBreached(password) {
  try {
    const hash = await hashPassword(password);
    const prefix = hash.slice(0, 5).toUpperCase();
    const suffix = hash.slice(5).toUpperCase();
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (!res.ok) return false;
    const text = await res.text();
    return text.split("\n").some((line) => line.startsWith(suffix));
  } catch {
    return false; // fail open if API is unreachable
  }
}

// Analyzes password strength and returns a score + feedback
export function analyzePassword(password) {
  const checks = {
    length: password.length >= 12,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    digits: /\d/.test(password),
    symbols: /[^A-Za-z0-9]/.test(password),
    noRepeats: !/(.)\1{2,}/.test(password),
    noCommon: !commonPatterns.some((p) => password.toLowerCase().includes(p)),
  };

  const score = Object.values(checks).filter(Boolean).length;

  const feedback = [];
  if (!checks.length) feedback.push("Use at least 12 characters");
  if (!checks.uppercase) feedback.push("Add uppercase letters");
  if (!checks.lowercase) feedback.push("Add lowercase letters");
  if (!checks.digits) feedback.push("Include numbers");
  if (!checks.symbols) feedback.push("Add special characters (!@#$%...)");
  if (!checks.noRepeats) feedback.push("Avoid repeated characters (aaa, 111)");
  if (!checks.noCommon) feedback.push("Avoid common words or patterns");

  const entropy = calculateEntropy(password);

  return { score, checks, feedback, entropy };
}

function calculateEntropy(password) {
  const charsets = [
    { regex: /[a-z]/, size: 26 },
    { regex: /[A-Z]/, size: 26 },
    { regex: /\d/, size: 10 },
    { regex: /[^A-Za-z0-9]/, size: 32 },
  ];
  const poolSize = charsets.reduce(
    (acc, c) => acc + (c.regex.test(password) ? c.size : 0),
    0
  );
  return poolSize > 0
    ? Math.floor(password.length * Math.log2(poolSize))
    : 0;
}

// Generates a strong random password
export function generateStrongPassword(length = 16) {
  const chars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}";
  const array = new Uint32Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, (x) => chars[x % chars.length]).join("");
}

const commonPatterns = [
  "password", "123456", "qwerty", "abc123", "letmein",
  "admin", "welcome", "monkey", "dragon", "master",
  "iloveyou", "sunshine", "princess", "football", "shadow",
];
