const enc = new TextEncoder();

/* ---------- helpers ---------- */
async function sha256(password: string) {
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(password));
  return [...new Uint8Array(hash)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function pbkdf2Hash(password: string, salt?: Uint8Array) {
  salt = salt || crypto.getRandomValues(new Uint8Array(16));

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
    hash: [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, "0")).join(""),
    salt: [...salt].map(b => b.toString(16).padStart(2, "0")).join("")
  };
}

async function pbkdf2Verify(password: string, hash: string, saltHex: string) {
  const salt = Uint8Array.from(
    saltHex.match(/.{1,2}/g)!.map(b => parseInt(b, 16))
  );
  const { hash: verify } = await pbkdf2Hash(password, salt);
  return verify === hash;
}

/* ---------- POST /auth/login ---------- */
export async function onRequestPost({ request, env }) {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store"
  };

  try {
    const { email, password } = await request.json();
    if (!email)
      return new Response(
        JSON.stringify({ error: "Missing email" }),
        { status: 400, headers }
      );

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

    if (!user)
      return new Response(
        JSON.stringify({ error: "Invalid credentials" }),
        { status: 401, headers }
      );

    /* ---------- GOOGLE LOGIN (SHORT-CIRCUIT) ---------- */
    if (user.provider === "google") {
      // Google users are always trusted
      if (user.verified !== 1) {
        await env.DB.prepare(
          "UPDATE users SET verified = 1 WHERE id = ?"
        ).bind(user.id).run();
      }

      const sessionId = crypto.randomUUID();
      await env.DB.prepare(
        "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
      ).bind(
        sessionId,
        user.id,
        Date.now() + 7 * 864e5
      ).run();

      return new Response(JSON.stringify({ success: true }), {
        headers: {
          ...headers,
          "Set-Cookie": `session=${sessionId}; HttpOnly; Secure; Path=/; SameSite=Lax`
        }
      });
    }

    /* ---------- EMAIL LOGIN ---------- */
    if (!password)
      return new Response(
        JSON.stringify({ error: "Missing password" }),
        { status: 400, headers }
      );

    if (user.verified !== 1)
      return new Response(
        JSON.stringify({ error: "Verify email first" }),
        { status: 403, headers }
      );

    let ok = false;

    // PBKDF2 (current)
    if (user.password_pbkdf2 && user.password_salt) {
      ok = await pbkdf2Verify(password, user.password_pbkdf2, user.password_salt);
    }
    // Legacy SHA-256 (auto-upgrade)
    else if (user.password_hash) {
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

    if (!ok)
      return new Response(
        JSON.stringify({ error: "Invalid credentials" }),
        { status: 401, headers }
      );

    const sessionId = crypto.randomUUID();
    await env.DB.prepare(
      "INSERT INTO users (id, user_id, expires_at) VALUES (?, ?, ?)"
    ).bind(
      sessionId,
      user.id,
      Date.now() + 7 * 864e5
    ).run();

    return new Response(JSON.stringify({ success: true }), {
      headers: {
        ...headers,
        "Set-Cookie": `session=${sessionId}; HttpOnly; Secure; Path=/; SameSite=Lax`
      }
    });

  } catch (e) {
    console.error("LOGIN ERROR:", e);
    return new Response(
      JSON.stringify({ error: "Server error" }),
      { status: 500, headers }
    );
  }
}
