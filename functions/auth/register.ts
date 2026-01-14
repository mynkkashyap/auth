const enc = new TextEncoder();

/* 🔐 PBKDF2 Hash Function */
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
  const headers = { 
    "Content-Type": "application/json",
    "Cache-Control": "no-store"
  };

  try {
    if (!env.DB || !env.RESEND_API_KEY || !env.BASE_URL) {
      throw new Error("Missing environment variables");
    }

    const body = await request.json();
    const { name = "", email, password, recaptchaToken } = body;
    
    // Get reCAPTCHA token from body or header
    const token = recaptchaToken || request.headers.get("X-Recaptcha-Token");
    
    if (!token) {
      return new Response(
        JSON.stringify({ error: "Missing reCAPTCHA token" }),
        { status: 400, headers }
      );
    }

    /* ------------------ Verify reCAPTCHA ------------------ */
    if (!env.RECAPTCHA_SECRET_KEY) {
      console.error("RECAPTCHA_SECRET_KEY is not set in environment");
      return new Response(
        JSON.stringify({ error: "Server configuration error" }),
        { status: 500, headers }
      );
    }

    const googleRes = await fetch(
      "https://www.google.com/recaptcha/api/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          secret: env.RECAPTCHA_SECRET_KEY,
          response: token,
        }),
      }
    );

    const captcha = await googleRes.json();

    // Debug logging (remove in production)
    console.log("reCAPTCHA response:", {
      success: captcha.success,
      score: captcha.score,
      action: captcha.action,
      hostname: captcha.hostname
    });

    if (!captcha.success || captcha.score < 0.5) {
      console.warn("reCAPTCHA failed:", {
        success: captcha.success,
        score: captcha.score,
        errors: captcha["error-codes"]
      });
      return new Response(
        JSON.stringify({ 
          error: "Security check failed. Please try again.",
          details: "reCAPTCHA verification failed"
        }),
        { status: 403, headers }
      );
    }

    // Optional: Verify the action if provided
    if (captcha.action && captcha.action !== "register") {
      console.warn("reCAPTCHA action mismatch:", captcha.action);
      // You can decide to be strict or lenient about this
      // return new Response(
      //   JSON.stringify({ error: "Invalid request action" }),
      //   { status: 400, headers }
      // );
    }

    /* ------------------ Validate Input ------------------ */
    if (!email || !password) {
      return new Response(
        JSON.stringify({ error: "Missing email or password" }),
        { status: 400, headers }
      );
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const normalizedEmail = email.toLowerCase().trim();
    
    if (!emailRegex.test(normalizedEmail)) {
      return new Response(
        JSON.stringify({ error: "Please enter a valid email address" }),
        { status: 400, headers }
      );
    }

    // Password validation
    if (password.length < 8) {
      return new Response(
        JSON.stringify({ error: "Password must be at least 8 characters long" }),
        { status: 400, headers }
      );
    }

    // Optional: Check password strength
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
      return new Response(
        JSON.stringify({ 
          error: "Password must contain uppercase, lowercase, numbers, and special characters" 
        }),
        { status: 400, headers }
      );
    }

    /* 🚫 BLOCK if Google account already exists */
    const googleUser = await env.DB.prepare(
      "SELECT id FROM users WHERE email = ? AND provider = 'google'"
    ).bind(normalizedEmail).first();

    if (googleUser) {
      return new Response(
        JSON.stringify({ 
          error: "This email is registered with Google Sign-In. Please use Google Sign-In instead.",
          provider: "google" 
        }),
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
            message: "Verification email resent. Please check your inbox.",
            needsVerification: true 
          }),
          { headers }
        );
      }

      return new Response(
        JSON.stringify({ error: "Email already registered" }),
        { status: 409, headers }
      );
    }

    /* 🆕 CREATE EMAIL USER */
    const { hash, salt } = await pbkdf2Hash(password);
    const verifyToken = generateToken();
    const userId = crypto.randomUUID();

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
        created_at,
        recaptcha_score
      )
      VALUES (?, ?, ?, ?, ?, 'email', 0, ?, ?, ?)
    `).bind(
      userId,
      name.trim(),
      normalizedEmail,
      hash,
      salt,
      verifyToken,
      Math.floor(Date.now() / 1000), // Unix timestamp
      captcha.score // Store reCAPTCHA score for analytics
    ).run();

    /* 📧 SEND VERIFICATION EMAIL (BEST-EFFORT) */
    await sendVerificationEmail(env, normalizedEmail, verifyToken);

    // Optional: Log successful registration for analytics
    await env.DB.prepare(`
      INSERT INTO registration_logs (user_id, email, recaptcha_score, created_at)
      VALUES (?, ?, ?, ?)
    `).bind(
      userId,
      normalizedEmail,
      captcha.score,
      Math.floor(Date.now() / 1000)
    ).run().catch(err => {
      console.warn("Failed to log registration:", err);
      // Don't fail the registration if logging fails
    });

    return new Response(
      JSON.stringify({ 
        success: true,
        message: "Registration successful! Please check your email to verify your account.",
        userId: userId
      }),
      { headers }
    );

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    return new Response(
      JSON.stringify({ 
        error: "An unexpected error occurred. Please try again later.",
        details: process.env.NODE_ENV === "development" ? err.message : undefined
      }),
      { status: 500, headers }
    );
  }
}

/* 📧 EMAIL SENDER (FAIL-SAFE) */
async function sendVerificationEmail(env: any, email: string, token: string) {
  try {
    const verifyUrl = `${env.BASE_URL}/auth/verify?token=${token}`;
    
    const response = await fetch("https://api.resend.com/emails", {
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
    <a href="${verifyUrl}"
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
    If the button doesn't work, copy and paste this link into your browser:
  </p>
  
  <p style="margin:8px 0 20px 0;
            padding:12px;
            background:#f9fafb;
            border-radius:6px;
            border:1px solid #e5e7eb;
            color:#4b5563;
            font-size:13px;
            word-break:break-all;">
    ${verifyUrl}
  </p>

  <p style="margin:20px 0 0 0;
            color:#6b7280;
            font-size:13px;
            line-height:1.5;">
    If you didn't create an account, you can safely ignore this email.
  </p>

  <p style="margin:12px 0 0 0;
            color:#9ca3af;
            font-size:12px;">
    This link will expire in 24 hours for security reasons.
  </p>

</div>`
      })
    });

    if (!response.ok) {
      const error = await response.text();
      console.error("RESEND API error:", error);
      throw new Error(`Email service failed: ${response.status}`);
    }

    console.log(`Verification email sent to ${email}`);
  } catch (e) {
    console.error("EMAIL ERROR:", e);
    // Don't throw - we don't want to fail registration if email fails
    // Just log it and continue
  }
}

/* ------------------ ENVIRONMENT VARIABLES REQUIRED ------------------ */
/*
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key_here
RESEND_API_KEY=your_resend_api_key_here
BASE_URL=https://yourdomain.com
*/

/* ------------------ OPTIONAL DATABASE SCHEMA EXTENSIONS ------------------ */
/*
-- Store reCAPTCHA score with user
ALTER TABLE users ADD COLUMN recaptcha_score REAL;

-- Registration logs for analytics
CREATE TABLE IF NOT EXISTS registration_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  email TEXT NOT NULL,
  recaptcha_score REAL,
  ip_address TEXT,
  user_agent TEXT,
  created_at INTEGER DEFAULT (unixepoch()),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index for faster queries
CREATE INDEX idx_registration_logs_created ON registration_logs(created_at);
CREATE INDEX idx_registration_logs_email ON registration_logs(email);
*/
