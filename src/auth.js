/**
 * Password hashing for the Workers runtime, which has WebCrypto but not scrypt.
 * PBKDF2-SHA256 with a random 16-byte salt, at 100k iterations — the ceiling the Workers
 * runtime allows (asking for more throws NotSupportedError). The count is stored inside the
 * hash, so raising it later only affects new passwords; old ones keep verifying at theirs.
 */
const ITERATIONS = 100_000;
const enc = new TextEncoder();

const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function derive(password, salt){
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" }, key, 256));
}

export async function hashPassword(password){
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${ITERATIONS}$${b64(salt)}$${b64(await derive(password, salt))}`;
}

export async function verifyPassword(password, stored){
  const [scheme, iter, salt, hash] = String(stored).split("$");
  if (scheme !== "pbkdf2" || !salt || !hash) return false;
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: unb64(salt), iterations: Number(iter) || ITERATIONS, hash: "SHA-256" }, key, 256));
  const want = unb64(hash);
  if (want.length !== bits.length) return false;
  let diff = 0;                                    // constant time
  for (let i = 0; i < want.length; i++) diff |= want[i] ^ bits[i];
  return diff === 0;
}

export function newToken(){
  return [...crypto.getRandomValues(new Uint8Array(32))].map(b => b.toString(16).padStart(2, "0")).join("");
}

export function validateCredentials(username, password){
  if (typeof username !== "string" || typeof password !== "string") return "Username and password are required.";
  if (!/^[A-Za-z0-9_-]{3,24}$/.test(username)) return "Usernames are 3–24 characters: letters, numbers, underscore or hyphen.";
  if (password.length < 8) return "Passwords need at least 8 characters.";
  if (password.length > 200) return "That password is too long.";
  return null;
}

/** Throttle stored in D1, so it survives the isolate being recycled. */
export async function rateLimit(db, key, max = 10, windowMs = 60_000){
  const now = Date.now();
  const row = await db.prepare("SELECT n, until FROM throttle WHERE k = ?").bind(key).first();
  if (!row || now > row.until){
    await db.prepare("INSERT INTO throttle (k, n, until) VALUES (?, 1, ?) ON CONFLICT(k) DO UPDATE SET n = 1, until = excluded.until")
      .bind(key, now + windowMs).run();
    return true;
  }
  await db.prepare("UPDATE throttle SET n = n + 1 WHERE k = ?").bind(key).run();
  return row.n + 1 <= max;
}

/* ---------- phone numbers and verification codes ---------- */

/**
 * Normalise to E.164, which is what an SMS gateway needs. A bare 10-digit number is
 * assumed to be US — both sites are for one US high-school course.
 */
export function normalizePhone(raw){
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim();
  const plus = trimmed.startsWith("+");
  const digits = trimmed.replace(/\D/g, "");
  if (!digits) return null;
  if (plus) return digits.length >= 8 && digits.length <= 15 ? "+" + digits : null;
  if (digits.length === 10) return "+1" + digits;
  if (digits.length === 11 && digits[0] === "1") return "+" + digits;
  return digits.length >= 8 && digits.length <= 15 ? "+" + digits : null;
}

/** All the browser is ever told about a stored number. */
export const phoneHint = e164 => "\u2022\u2022\u2022\u2022 " + String(e164).slice(-4);

/** Six digits, uniformly distributed (reject the tail rather than take the modulo bias). */
export function newCode(){
  const max = Math.floor(0xFFFFFFFF / 1000000) * 1000000;
  let n = crypto.getRandomValues(new Uint32Array(1))[0];
  while (n >= max) n = crypto.getRandomValues(new Uint32Array(1))[0];
  return String(n % 1000000).padStart(6, "0");
}

/**
 * Codes are stored salted-and-hashed so a leaked table is not a list of live codes.
 * SHA-256 rather than PBKDF2 on purpose: a six-digit code has too small a space for any
 * hash to save it, so the real defences are the ten-minute expiry, the five-try limit and
 * single use — and this runs on every verify, where PBKDF2 would burn the CPU budget.
 */
export async function hashCode(code, salt){
  const bytes = new TextEncoder().encode(salt + ":" + code);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

export function newSalt(){
  return [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, "0")).join("");
}

/** Store as "salt$hash". */
export async function sealCode(code){
  const salt = newSalt();
  return salt + "$" + await hashCode(code, salt);
}

export async function checkCode(code, stored){
  const [salt, want] = String(stored).split("$");
  if (!salt || !want) return false;
  const got = await hashCode(code, salt);
  if (got.length !== want.length) return false;
  let diff = 0;
  for (let i = 0; i < got.length; i++) diff |= got.charCodeAt(i) ^ want.charCodeAt(i);
  return diff === 0;
}

export const CODE_TTL_MS = 10 * 60 * 1000;
export const MAX_CODE_TRIES = 5;
export const MAX_CODE_SENDS = 4;
