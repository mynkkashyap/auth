import { sha256, pbkdf2Hash, pbkdf2Verify } from './auth-utils'; // Move these to a separate file

export async function onRequestPost({ request, env }) {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  };

  try {
    const body = await request.json();
    const { email, password, recaptchaToken } = body;
    
    // Get reCAPTCHA token from body or header
    const token = recaptchaToken || request.headers.get("X-Recaptcha-Token");
    
    if (!token) {
      return new Response(
        JSON.stringify({ error: "Missing reCAPTCHA token" }),
        { status: 400, headers }
      );
    }

    /* ------------------ Verify reCAPTCHA ------------------ */
    const googleRes = await fetch(
      "https://www.google.com/recaptcha/api/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          secret: env.RECAPTCHA_SECRET,
          response: token,
        }),
      }
    );

    const captcha = await googleRes.json();

    if (!captcha.success || captcha.score < 0.5 || captcha.action !== "login") {
      return new Response(
        JSON.stringify({ error: "reCAPTCHA failed" }),
        { status: 403, headers }
      );
    }

    /* ------------------ Authenticate user ------------------ */
    if (!email) {
      return new Response(
        JSON.stringify({ error: "Missing email" }),
        { status: 400, headers }
      );
    }

    const normalizedEmail = email.toLowerCase().trim();

    const user = await env.DB.prepare(`
      SELECT
        id,
        provider,
        verified,
        password_hash,
        password_pbkdf2,
        password_salt
      FROM users
      WHERE email = ?
    `).bind(normalizedEmail).first();

    if (!user) {
      return new Response(
        JSON.stringify({ error: "Invalid credentials" }),
        { status: 401, headers }
      );
    }

    /* 🚫 BLOCK GOOGLE USERS */
    if (user.provider === "google") {
      return new Response(
        JSON.stringify({ error: "Use Google Sign-In" }),
        { status: 409, headers }
      );
    }

    /* ---------- EMAIL LOGIN ---------- */
    if (!password) {
      return new Response(
        JSON.stringify({ error: "Missing password" }),
        { status: 400, headers }
      );
    }

    if (user.verified !== 1) {
      return new Response(
        JSON.stringify({ error: "Verify email first" }),
        { status: 403, headers }
      );
    }

    let ok = false;

    if (user.password_pbkdf2 && user.password_salt) {
      ok = await pbkdf2Verify(
        password,
        user.password_pbkdf2,
        user.password_salt
      );
    } else if (user.password_hash) {
      // Migrate from SHA-256 to PBKDF2
      ok = (await sha256(password)) === user.password_hash;

      if (ok) {
        const { hash, salt } = await pbkdf2Hash(password);
        await env.DB.prepare(`
          UPDATE users
          SET password_pbkdf2 = ?, password_salt = ?, password_hash = NULL
          WHERE id = ?
        `).bind(hash, salt, user.id).run();
      }
    }

    if (!ok) {
      return new Response(
        JSON.stringify({ error: "Invalid credentials" }),
        { status: 401, headers }
      );
    }

    // Create session
    const sessionId = crypto.randomUUID();
    const expiresAt = Date.now() + 7 * 86400 * 1000; // 7 days

    await env.DB.prepare(
      "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
    ).bind(
      sessionId,
      user.id,
      expiresAt
    ).run();

    return new Response(
      JSON.stringify({ 
        success: true,
        message: "Login successful",
        redirectUrl: "/dashboard.html"
      }),
      {
        status: 200,
        headers: {
          ...headers,
          "Set-Cookie": `session=${sessionId}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=${7 * 86400}`,
        },
      }
    );

  } catch (e) {
    console.error("LOGIN ERROR:", e);
    return new Response(
      JSON.stringify({ error: "Server error" }),
      { status: 500, headers }
    );
  }
}
