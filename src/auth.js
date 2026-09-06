/**
 * Password hashing for the Workers runtime, which has WebCrypto but not scrypt.
 * PBKDF2-SHA256, 210k iterations (OWASP's 2023 floor), random 16-byte salt.
 */
const ITERATIONS = 210_000;
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
