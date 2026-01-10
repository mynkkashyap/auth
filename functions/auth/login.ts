const enc = new TextEncoder();

/* ================================
   🔐 SHA-256 (legacy support only)
================================ */
async function sha256(password: string) {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    enc.encode(password)
  );
  return [...new Uint8Array(hash)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

/* ================================
   🔐 PBKDF2 helpers (production)
================================ */
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
    {
      name: "PBKDF2",
      salt,
      iterations: 100_000,
      hash: "SHA-256"
    },
    key,
    256
  );

  return {
    hash: Array.from(new Uint8Array(bits))
      .map(b => b.toString(16).padStart(2, "0"))
      .join(""),
    salt: Array.from(salt)
      .map(b => b.toString(16).padStart(2, "0"))
      .join("")
  };
}

async function pbkdf2Verify(
  password: string,
  hash: string,
  saltHex: string
) {
  const salt = Uint8Array.from(
    saltHex.match(/.{1,2}/g)!.map(b => parseInt(b, 16))
  );
  const { hash: verifyHash } = await pbkdf2Hash(password, salt);
  return verifyHash === hash;
}

/* ================================
   🚫 Block GET
================================ */
export async function onRequestGet() {
  return new Response("Method Not Allowed", { status: 405 });
}

/* ================================
   ✅ POST – LOGIN
================================ */
export async function onRequestPost({ request, env }) {
  if (!env.DB) {
    return Response.json({ error: "DB binding missing" }, { status: 500 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const { email, password } = body;

  if (!email || !password) {
    return Response.json(
      { error: "Missing email or password" },
      { status: 400 }
    );
  }

  const user = await env.DB.prepare(
    `
    SELECT
      id,
      verified,
      provider,
      password_hash,
      password_pbkdf2,
      password_salt
    FROM users
    WHERE email = ?
    `
  ).bind(email).first();

  if (!user) {
    return Response.json({ error: "Invalid credentials" }, { status: 401 });
  }

  /* 🚫 Email must be verified (email users only) */
  if (user.provider === "email" && !user.verified) {
    return Response.json(
      { error: "Please verify your email before logging in" },
      { status: 403 }
    );
  }

  let passwordOK = false;

  /* 🟢 Google users */
  if (user.provider === "google") {
    passwordOK = true;
  }

  /* 🟢 PBKDF2 users */
  else if (user.password_pbkdf2 && user.password_salt) {
    passwordOK = await pbkdf2Verify(
      password,
      user.password_pbkdf2,
      user.password_salt
    );
  }

  /* 🟡 Legacy SHA-256 users → auto-migrate */
  else if (user.password_hash) {
    const legacyHash = await sha256(password);
    passwordOK = legacyHash === user.password_hash;

    if (passwordOK) {
      const { hash, salt } = await pbkdf2Hash(password);

      await env.DB.prepare(
        `
        UPDATE users
        SET password_pbkdf2 = ?, password_salt = ?, password_hash = NULL
        WHERE id = ?
        `
      ).bind(hash, salt, user.id).run();
    }
  }

  if (!passwordOK) {
    return Response.json({ error: "Invalid credentials" }, { status: 401 });
  }

  /* 🔐 CREATE SESSION */
  const sessionId = crypto.randomUUID();
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;

  await env.DB.prepare(
    `
    INSERT INTO sessions (id, user_id, expires_at)
    VALUES (?, ?, ?)
    `
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
