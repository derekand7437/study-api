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
    console.error("sms send failed:", res.status, detail.slice(0, 400));

    // Twilio's own message can name the account, so it is never passed straight through.
    // These are the setup mistakes that actually happen, turned into something actionable.
    let code = 0;
    try { code = Number(JSON.parse(detail).code) || 0; } catch {}
    const known = {
      20003: "The texting account is not set up correctly (its credentials were rejected).",
      21608: "This number has not been verified with the texting account yet. On a Twilio trial you can only text numbers you have verified in the Twilio console.",
      21211: "That does not look like a real phone number.",
      21214: "That does not look like a real phone number.",
      21606: "The texting account's own number is not set up correctly.",
      21612: "That number cannot be texted from this account.",
      21614: "That number cannot receive text messages \u2014 try a mobile number.",
      21610: "That number has replied STOP, so it cannot be texted."
    };
    return { ok: false, error: known[code] || "Could not send the code. Check the number and try again." };
  } catch (err){
    console.error("sms send threw:", err);
    return { ok: false, error: "Could not send the code just now." };
  }
}
