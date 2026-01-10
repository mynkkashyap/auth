async function sha256(password: string) {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    enc.encode(password)
  );
  return [...new Uint8Array(hash)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function onRequestPost({ request, env }) {
  const { email, password } = await request.json();

  const user = await env.DB.prepare(
    `SELECT id, verified, password_hash, password_pbkdf2, password_salt
     FROM users WHERE email = ?`
  ).bind(email).first();

  if (!user) {
    return Response.json({ error: "Invalid credentials" }, { status: 401 });
  }

  if (!user.verified) {
    return Response.json(
      { error: "Please verify your email first" },
      { status: 403 }
    );
  }

  let passwordOK = false;

  // 🟢 PBKDF2 USER
  if (user.password_pbkdf2 && user.password_salt) {
    passwordOK = await pbkdf2Verify(
      password,
      user.password_pbkdf2,
      user.password_salt
    );
  }

  // 🟡 OLD SHA-256 USER → MIGRATE
  else if (user.password_hash) {
    const legacyHash = await sha256(password);
    passwordOK = legacyHash === user.password_hash;

    if (passwordOK) {
      const { hash, salt } = await pbkdf2Hash(password);

      await env.DB.prepare(
        `UPDATE users
         SET password_pbkdf2 = ?, password_salt = ?, password_hash = NULL
         WHERE id = ?`
      ).bind(hash, salt, user.id).run();
    }
  }

  if (!passwordOK) {
    return Response.json({ error: "Invalid credentials" }, { status: 401 });
  }

  // 🔐 SESSION
  const sessionId = crypto.randomUUID();
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;

  await env.DB.prepare(
    "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
  ).bind(sessionId, user.id, expiresAt).run();

  return Response.json(
    { success: true },
    {
      headers: {
        "Set-Cookie": `session=${sessionId}; HttpOnly; Secure; Path=/; SameSite=Lax`,
        "Cache-Control": "no-store"
      }
    }
  );
}
