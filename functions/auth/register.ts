const enc = new TextEncoder();

/* 🔐 PBKDF2 */
async function pbkdf2Hash(password: string) {
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100_000, hash: "SHA-256" },
    key,
    256
  );

  return {
    hash: [...new Uint8Array(bits)]
      .map(b => b.toString(16).padStart(2, "0"))
      .join(""),
    salt: [...salt]
      .map(b => b.toString(16).padStart(2, "0"))
      .join("")
  };
}

/* 🔑 Email verification token */
function generateToken() {
  return crypto.randomUUID().replace(/-/g, "");
}

/* ❌ Block GET */
export async function onRequestGet() {
  return new Response("POST only", { status: 405 });
}

/* ✅ POST /auth/register */
export async function onRequestPost({ request, env }) {
  const headers = { "Content-Type": "application/json" };

  try {
    if (!env.DB || !env.RESEND_API_KEY || !env.BASE_URL) {
      throw new Error("Missing env vars");
    }

    const { name = "", email, password } = await request.json();

    if (!email || !password) {
      return new Response(
        JSON.stringify({ error: "Missing email or password" }),
        { status: 400, headers }
      );
    }

    const normalizedEmail = email.toLowerCase().trim();

    /* 🚫 BLOCK if Google account already exists */
    const googleUser = await env.DB.prepare(
      "SELECT id FROM users WHERE email = ? AND provider = 'google'"
    ).bind(normalizedEmail).first();

    if (googleUser) {
      return new Response(
        JSON.stringify({ error: "Use Google Sign-In for this email" }),
        { status: 409, headers }
      );
    }

    /* 🔍 CHECK EXISTING EMAIL USER ONLY */
    const existing = await env.DB.prepare(
      "SELECT verified, verify_token FROM users WHERE email = ? AND provider = 'email'"
    ).bind(normalizedEmail).first();

    /* 🔁 EXISTS BUT NOT VERIFIED → RESEND */
    if (existing) {
      if (existing.verified === 0) {
        await sendVerificationEmail(env, normalizedEmail, existing.verify_token);
        return new Response(
          JSON.stringify({ success: true, message: "Verification email resent" }),
          { headers }
        );
      }

      return new Response(
        JSON.stringify({ error: "Email already exists" }),
        { status: 409, headers }
      );
    }

    /* 🆕 CREATE EMAIL USER */
    const { hash, salt } = await pbkdf2Hash(password);
    const verifyToken = generateToken();

    await env.DB.prepare(`
      INSERT INTO users (
        id,
        name,
        email,
        password_pbkdf2,
        password_salt,
        provider,
        verified,
        verify_token
      )
      VALUES (?, ?, ?, ?, ?, 'email', 0, ?)
    `).bind(
      crypto.randomUUID(),
      name,
      normalizedEmail,
      hash,
      salt,
      verifyToken
    ).run();

    /* 📧 SEND VERIFICATION EMAIL (BEST-EFFORT) */
    await sendVerificationEmail(env, normalizedEmail, verifyToken);

    return new Response(
      JSON.stringify({ success: true }),
      { headers }
    );

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers }
    );
  }
}

/* 📧 EMAIL SENDER (FAIL-SAFE) */
async function sendVerificationEmail(env: any, email: string, token: string) {
  try {
    await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: "Auth <onboarding@auth.medr.in>",
        to: email,
        subject: "Verify your account",
        html: `
          <p>Verify your account:</p>
          <a href="${env.BASE_URL}/auth/verify?token=${token}">
            Verify Email
          </a>
        `
      })
    });
  } catch (e) {
    console.error("EMAIL ERROR (ignored):", e);
  }
}
