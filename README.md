# study-api

Accounts and saved progress for the two study sites, on Cloudflare Workers + D1.

One API serves both subjects. Because the sites share an origin (`derekand7437.github.io`),
one account and one sign-in covers chemistry *and* geometry.

Free tier, no credit card, and D1 is a real database — data survives restarts and redeploys.

## Deploying it

```bash
cd ~/study-api

npx wrangler login                       # opens your browser once
npx wrangler d1 create study             # prints a database_id — paste it into wrangler.toml
npx wrangler d1 execute study --remote --file schema.sql
npx wrangler deploy                      # prints your API URL
```

The last command prints something like `https://study-api.your-name.workers.dev`.
Put that URL into `js/config.js` in **both** site repos:

```js
const WORKER_URL = "https://study-api.your-name.workers.dev";
```

Then `git commit` and `git push` each site. A minute later the live sites have accounts.

## Developing locally

```bash
npx wrangler d1 execute study --local --file schema.sql
npx wrangler dev --local                 # http://localhost:8787
```

To point a locally served site at it, add `?api=http://localhost:8787` to the page URL.

## The API

| Method | Path | Does |
|---|---|---|
| GET | `/api/health` | is the backend up |
| POST | `/api/register` · `/login` · `/logout` | accounts |
| GET | `/api/me` | who am I |
| POST | `/api/verify` | step two: the texted code |
| POST | `/api/resend` | text the code again |
| GET/PUT | `/api/prefs` | appearance settings, shared by both subjects |
| GET/PUT | `/api/progress/:subject` | saved progress (`chemistry` or `geometry`) |
| POST | `/api/attempts` | log answered problems, in batches |
| GET | `/api/stats` | progress, accuracy by topic, last 30 days |

## Two-step verification

Signing up asks for a phone number; signing in asks for the code texted to it. The password
alone never returns a session — it returns a short-lived challenge, and only the right code
turns that into a token. A signup is not an account until its number is verified, so an
abandoned one leaves nothing behind.

Workers cannot send SMS, so this needs Twilio (or any provider you adapt `src/sms.js` to).
**Until those three secrets exist the code step is switched off** and signup and login stay
one step — a code step with no way to deliver a code would lock everyone out. Phone numbers
are collected either way.

### Turning texting on

1. Make a Twilio account at <https://www.twilio.com/try-twilio> and get a phone number
   (Develop → Phone Numbers → Buy a number; a trial comes with credit for one).
2. From the console dashboard copy the **Account SID** and **Auth Token**.
3. Run these in `~/study-api`, pasting each value when prompted:

```bash
npx wrangler secret put TWILIO_SID       # starts with AC
npx wrangler secret put TWILIO_TOKEN
npx wrangler secret put TWILIO_FROM      # your Twilio number, e.g. +15551234567
npx wrangler deploy
```

4. Check it took:

```bash
curl -s https://study-api.study-api.workers.dev/api/health
# {"ok":true,...,"twoFactor":true}
```

**A trial account can only text numbers you have verified with Twilio** (console →
Phone Numbers → Verified Caller IDs). That is fine for testing on your own phone; texting
classmates needs the account upgraded. If a send fails, the API says why — an unverified
number, bad credentials and a landline all give their own message.

`GET /api/health` reports `twoFactor: true` once it is live. Texts are not free — Twilio
charges per message, and a trial account can only text numbers you have verified with them.

Codes are six digits, expire in ten minutes, are single use, allow five wrong guesses before
they are burned, and can be re-sent four times. They are stored salted and hashed, so the
table is not a list of live codes. The number is never sent back to the browser — only a
`•••• 1234` hint.

## Security

Passwords are hashed with PBKDF2-SHA256 at 100,000 iterations and a random 16-byte salt,
compared in constant time. 100,000 is the ceiling the Workers runtime allows — asking for
more throws `NotSupportedError` — and the count is stored in the hash, so it can be raised
later without invalidating existing passwords. Session tokens are 32 random bytes and are
deleted on sign-out.

CORS is closed by default: only the origins in `ALLOWED_ORIGINS` (in `wrangler.toml`) and
`localhost` may call the API. Register is capped at 40 new accounts per hour per IP and
sign-in at 40 attempts per five minutes — generous, because a whole class shares one school
IP address. The throttle lives in D1, so restarting the Worker does not reset it.

Request bodies are capped at 256 KB, and every write is bound through prepared statements.
