-- Cloudflare D1 (SQLite). Applied with:  npx wrangler d1 execute study --file schema.sql
CREATE TABLE IF NOT EXISTS users (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  pass     TEXT NOT NULL,
  created  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token   TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS progress (
  user_id INTEGER NOT NULL,
  subject TEXT NOT NULL,
  data    TEXT NOT NULL,
  updated TEXT NOT NULL,
  PRIMARY KEY (user_id, subject)
);
CREATE TABLE IF NOT EXISTS prefs (
  user_id INTEGER PRIMARY KEY,
  data    TEXT NOT NULL,
  updated TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attempts (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  subject TEXT NOT NULL,
  topic   TEXT NOT NULL,
  correct INTEGER NOT NULL,
  day     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS attempts_user ON attempts(user_id, day);
CREATE TABLE IF NOT EXISTS throttle (
  k     TEXT PRIMARY KEY,
  n     INTEGER NOT NULL,
  until INTEGER NOT NULL
);
