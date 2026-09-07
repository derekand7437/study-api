/**
 * Sending the verification code.
 *
 * Workers cannot send SMS on their own, so this talks to Twilio over its REST API. It stays
 * dormant until the three secrets exist, and `configured()` is what decides whether the rest
 * of the API asks for a code at all — a half-working code step would lock everyone out.
 *
 *   npx wrangler secret put TWILIO_SID
 *   npx wrangler secret put TWILIO_TOKEN
 *   npx wrangler secret put TWILIO_FROM     # the Twilio number, e.g. +15551234567
 */
export const configured = env => !!(env.TWILIO_SID && env.TWILIO_TOKEN && env.TWILIO_FROM);

export async function sendCode(env, to, code){
  if (!configured(env)) return { ok: false, error: "SMS is not configured." };
  // TWILIO_API_BASE exists so the code path can be exercised against a stand-in gateway.
  const base = env.TWILIO_API_BASE || "https://api.twilio.com";
  const url = `${base}/2010-04-01/Accounts/${encodeURIComponent(env.TWILIO_SID)}/Messages.json`;
  const body = new URLSearchParams({
    To: to, From: env.TWILIO_FROM,
    Body: `${code} is your verification code. It expires in 10 minutes.`
  });
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: "Basic " + btoa(`${env.TWILIO_SID}:${env.TWILIO_TOKEN}`),
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body
    });
    if (res.ok) return { ok: true };
    const detail = await res.text();
    console.error("sms send failed:", res.status, detail.slice(0, 300));
    // Never echo the provider's message back to the browser: it leaks account details.
    return { ok: false, error: "Could not send the code. Check the number and try again." };
  } catch (err){
    console.error("sms send threw:", err);
    return { ok: false, error: "Could not send the code just now." };
  }
}
