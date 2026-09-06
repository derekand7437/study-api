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
| GET/PUT | `/api/progress/:subject` | saved progress (`chemistry` or `geometry`) |
| POST | `/api/attempts` | log answered problems, in batches |
| GET | `/api/stats` | progress, accuracy by topic, last 30 days |

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
