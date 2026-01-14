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

/* 🔒 Google reCAPTCHA validation */
async function verifyRecaptcha(token: string, env: any): Promise<boolean> {
  try {
    const secretKey = env.RECAPTCHA_SECRET_KEY; // You need to add this to your env vars
    
    if (!secretKey) {
      console.warn("RECAPTCHA_SECRET_KEY not set, skipping validation");
      return true; // Or false depending on your requirements
    }

    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `secret=${encodeURIComponent(secretKey)}&response=${encodeURIComponent(token)}`
    });

    const data = await response.json();
    
    // Check if reCAPTCHA verification was successful
    // You can also check data.score for a threshold (e.g., > 0.5)
    return data.success === true && data.score > 0.5; // Adjust threshold as needed
  } catch (error) {
    console.error('reCAPTCHA verification failed:', error);
    return false;
  }
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

    const { name = "", email, password, recaptchaToken } = await request.json();

    // Get token from header as fallback
    const tokenFromHeader = request.headers.get("X-Recaptcha-Token");
    const recaptchaTokenToVerify = recaptchaToken || tokenFromHeader;

    if (!email || !password) {
      return new Response(
        JSON.stringify({ error: "Missing email or password" }),
        { status: 400, headers }
      );
    }

    // Validate reCAPTCHA
    if (recaptchaTokenToVerify) {
      const isRecaptchaValid = await verifyRecaptcha(recaptchaTokenToVerify, env);
      if (!isRecaptchaValid) {
        return new Response(
          JSON.stringify({ error: "Failed reCAPTCHA verification. Please try again." }),
          { status: 400, headers }
        );
      }
    } else {
      // Optional: Decide if reCAPTCHA is required
      // For production, you might want to make it required
      console.warn("No reCAPTCHA token provided");
      // return new Response(
      //   JSON.stringify({ error: "reCAPTCHA token required" }),
      //   { status: 400, headers }
      // );
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
          JSON.stringify({ 
            success: true, 
            message: "Verification email resent",
            redirectUrl: "/verify-pending.html"
          }),
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
        verify_token,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, 'email', 0, ?, datetime('now'))
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
      JSON.stringify({ 
        success: true,
        message: "Account created! Please check your email to verify your account.",
        redirectUrl: "/verify-pending.html"
      }),
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
          <div style="max-width:520px;margin:0 auto;padding:24px;
            font-family:Arial,Helvetica,sans-serif;
            background:#ffffff;border-radius:10px;
            box-shadow:0 4px 12px rgba(0,0,0,0.08);
            border:1px solid #e5e7eb;">

  <h2 style="margin:0 0 12px 0;
             color:#111827;
             font-size:22px;
             font-weight:600;">
    Verify Your Email Address
  </h2>

  <p style="margin:0 0 20px 0;
            color:#4b5563;
            font-size:15px;
            line-height:1.6;">
    Thank you for signing up! Please confirm your email address by clicking the button below.
  </p>

  <div style="text-align:center;margin:28px 0;">
    <a href="${env.BASE_URL}/auth/verify?token=${token}"
       style="display:inline-block;
              padding:12px 26px;
              background:#2563eb;
              color:#ffffff;
              text-decoration:none;
              font-size:15px;
              font-weight:600;
              border-radius:6px;">
      Verify Email
    </a>
  </div>

  <p style="margin:20px 0 0 0;
            color:#6b7280;
            font-size:13px;
            line-height:1.5;">
    If you didn't create an account, you can safely ignore this email.
  </p>

  <p style="margin:12px 0 0 0;
            color:#9ca3af;
            font-size:12px;">
    This link will expire for security reasons.
  </p>

</div>`
      })
    });
  } catch (e) {
    console.error("EMAIL ERROR (ignored):", e);
  }
}
