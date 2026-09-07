/**
 * The study API on Cloudflare Workers + D1.
 *
 * Serves both subject sites, which live on the same origin (GitHub Pages), so one account
 * and one sign-in covers chemistry and geometry together.
 */
import { hashPassword, verifyPassword, newToken, validateCredentials, rateLimit } from "./auth.js";

const SUBJECTS = new Set(["chemistry", "geometry"]);
const MAX_BODY = 256 * 1024;

function allowedOrigin(request, env){
  const origin = request.headers.get("Origin");
  if (!origin) return null;
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
  if (allowed.includes(origin)) return origin;
  if (/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return origin;   // local development
  return null;
}

function cors(origin){
  return origin ? {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  } : {};
}

const json = (status, payload, origin) => new Response(JSON.stringify(payload), {
  status, headers: { "Content-Type": "application/json; charset=utf-8", ...cors(origin) }
});

async function readBody(request){
  const len = Number(request.headers.get("Content-Length") || 0);
  if (len > MAX_BODY) throw new Error("body too large");
  const text = await request.text();
  if (text.length > MAX_BODY) throw new Error("body too large");
  if (!text) return {};
  try { return JSON.parse(text); } catch { throw new Error("invalid JSON"); }
}

function tokenFrom(request, url){
  const header = request.headers.get("Authorization") || "";
  if (header.startsWith("Bearer ")) return header.slice(7).trim();
  return url.searchParams.get("token") || null;      // sendBeacon cannot set headers
}

async function userFor(db, token){
  if (!token) return null;
  return db.prepare(
    "SELECT u.id, u.username, u.created FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?"
  ).bind(token).first();
}

export default {
  async fetch(request, env){
    const url = new URL(request.url);
    const origin = allowedOrigin(request, env);
    const db = env.DB;

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(origin) });

    const path = url.pathname.replace(/^\/api/, "") || "/";
    const ip = request.headers.get("CF-Connecting-IP") || "?";
    const out = (status, payload) => json(status, payload, origin);

    try {
      if (path === "/health" && request.method === "GET")
        return out(200, { ok: true, subjects: [...SUBJECTS] });

      /* ---------- accounts ---------- */
      if (path === "/register" && request.method === "POST"){
        // a whole class often shares one school IP, so this is generous by design
        if (!await rateLimit(db, "reg:" + ip, 40, 3_600_000))
          return out(429, { error: "Too many new accounts from here just now. Try again later." });
        const { username, password } = await readBody(request);
        const bad = validateCredentials(username, password);
        if (bad) return out(400, { error: bad });
        if (await db.prepare("SELECT id FROM users WHERE username = ?").bind(username).first())
          return out(409, { error: "That username is taken." });

        const now = new Date().toISOString();
        await db.prepare("INSERT INTO users (username, pass, created) VALUES (?, ?, ?)")
          .bind(username, await hashPassword(password), now).run();
        const user = await db.prepare("SELECT id, username, created FROM users WHERE username = ?").bind(username).first();
        const token = newToken();
        await db.prepare("INSERT INTO sessions (token, user_id, created) VALUES (?, ?, ?)").bind(token, user.id, now).run();
        return out(201, { token, user });
      }

      if (path === "/login" && request.method === "POST"){
        if (!await rateLimit(db, "login:" + ip, 40, 300_000))
          return out(429, { error: "Too many sign-in attempts. Wait a few minutes." });
        const { username, password } = await readBody(request);
        if (typeof username !== "string" || typeof password !== "string")
          return out(400, { error: "Username and password are required." });
        const row = await db.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
        if (!row || !await verifyPassword(password, row.pass))
          return out(401, { error: "Wrong username or password." });
        const token = newToken();
        await db.prepare("INSERT INTO sessions (token, user_id, created) VALUES (?, ?, ?)")
          .bind(token, row.id, new Date().toISOString()).run();
        return out(200, { token, user: { id: row.id, username: row.username, created: row.created } });
      }

      if (path === "/logout" && request.method === "POST"){
        const t = tokenFrom(request, url);
        if (t) await db.prepare("DELETE FROM sessions WHERE token = ?").bind(t).run();
        return out(200, { ok: true });
      }

      const user = await userFor(db, tokenFrom(request, url));
      const need = () => out(401, { error: "Sign in first." });

      if (path === "/me" && request.method === "GET")
        return user ? out(200, { user }) : need();

      /* ---------- appearance settings, shared by both subjects ---------- */
      if (path === "/prefs"){
        if (!user) return need();

        if (request.method === "GET"){
          const row = await db.prepare("SELECT data, updated FROM prefs WHERE user_id = ?").bind(user.id).first();
          return out(200, { data: row ? JSON.parse(row.data) : null, updated: row ? row.updated : null });
        }
        if (request.method === "PUT"){
          const { data } = await readBody(request);
          if (!data || typeof data !== "object" || Array.isArray(data))
            return out(400, { error: "Expected a settings object." });
          const updated = new Date().toISOString();
          await db.prepare(`INSERT INTO prefs (user_id, data, updated) VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated = excluded.updated`)
            .bind(user.id, JSON.stringify(data), updated).run();
          return out(200, { ok: true, updated });
        }
      }

      /* ---------- progress ---------- */
      const prog = path.match(/^\/progress\/([a-z]+)$/);
      if (prog){
        if (!user) return need();
        const subject = prog[1];
        if (!SUBJECTS.has(subject)) return out(404, { error: "Unknown subject." });

        if (request.method === "GET"){
          const row = await db.prepare("SELECT data, updated FROM progress WHERE user_id = ? AND subject = ?")
            .bind(user.id, subject).first();
          return out(200, { data: row ? JSON.parse(row.data) : null, updated: row ? row.updated : null });
        }
        if (request.method === "PUT"){
          const { data } = await readBody(request);
          if (!data || typeof data !== "object") return out(400, { error: "Expected a progress object." });
          const updated = new Date().toISOString();
          await db.prepare(`INSERT INTO progress (user_id, subject, data, updated) VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id, subject) DO UPDATE SET data = excluded.data, updated = excluded.updated`)
            .bind(user.id, subject, JSON.stringify(data), updated).run();
          return out(200, { ok: true, updated });
        }
      }

      /* ---------- attempts and stats ---------- */
      if (path === "/attempts" && request.method === "POST"){
        if (!user) return need();
        const { attempts } = await readBody(request);
        if (!Array.isArray(attempts)) return out(400, { error: "Expected an attempts array." });
        const rows = attempts.filter(a => a && SUBJECTS.has(a.subject) && typeof a.topic === "string").slice(0, 500);
        if (rows.length){
          const stmt = db.prepare("INSERT INTO attempts (user_id, subject, topic, correct, day) VALUES (?, ?, ?, ?, ?)");
          await db.batch(rows.map(r => stmt.bind(
            user.id, r.subject, String(r.topic).slice(0, 32), r.correct ? 1 : 0,
            new Date(Number(r.at) || Date.now()).toISOString().slice(0, 10))));
        }
        return out(200, { ok: true, stored: rows.length });
      }

      if (path === "/stats" && request.method === "GET"){
        if (!user) return need();
        const from = new Date(Date.now() - 30 * 864e5).toISOString().slice(0, 10);
        const [progressRows, topics, daily] = await Promise.all([
          db.prepare("SELECT subject, data FROM progress WHERE user_id = ?").bind(user.id).all(),
          db.prepare(`SELECT subject, topic, COUNT(*) AS total, SUM(correct) AS right
                      FROM attempts WHERE user_id = ? GROUP BY subject, topic ORDER BY total DESC`).bind(user.id).all(),
          db.prepare(`SELECT day, COUNT(*) AS total, SUM(correct) AS right
                      FROM attempts WHERE user_id = ? AND day >= ? GROUP BY day ORDER BY day`).bind(user.id, from).all()
        ]);
        const progress = {};
        for (const row of progressRows.results) progress[row.subject] = JSON.parse(row.data);
        return out(200, { user, progress, topics: topics.results, daily: daily.results });
      }

      return out(404, { error: "No such endpoint." });
    } catch (err){
      const known = err.message === "invalid JSON" || err.message === "body too large";
      if (!known) console.error("request failed:", err);
      return out(known ? 400 : 500, { error: known ? err.message : "Server error." });
    }
  }
};
