export async function onRequestPost({ request, env }) {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  };

  try {
    const { email, password } = await request.json();

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

    const sessionId = crypto.randomUUID();

    await env.DB.prepare(
      "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
    ).bind(
      sessionId,
      user.id,
      Date.now() + 7 * 864e5
    ).run();

    return new Response(
      JSON.stringify({ success: true }),
      {
        headers: {
          ...headers,
          "Set-Cookie": `session=${sessionId}; HttpOnly; Secure; Path=/; SameSite=Lax`,
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
