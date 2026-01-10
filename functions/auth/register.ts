const enc = new TextEncoder();

/* 🔐 PBKDF2 helper */
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

/* 🔑 Verification token */
function generateToken() {
  return crypto.randomUUID().replace(/-/g, "");
}

/* ❌ Block GET requests */
export async function onRequestGet() {
  return new Response(
    "This endpoint only accepts POST requests",
    { status: 405 }
  );
}

/* ✅ POST – Register */
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

  const { name = "", email, password } = body;

  if (!email || !password) {
    return Response.json(
      { error: "Missing email or password" },
      { status: 400 }
    );
  }

  const { hash, salt } = await pbkdf2Hash(password);
  const verifyToken = generateToken();

  try {
    await env.DB.prepare(
      `
      INSERT INTO users
      (id, name, email, password_pbkdf2, password_salt, provider, verified, verify_token)
      VALUES (?, ?, ?, ?, ?, 'email', 0, ?)
      `
    )
      .bind(
        crypto.randomUUID(),
        name,
        email,
        hash,
        salt,
        verifyToken
      )
      .run();
  } catch {
    return Response.json(
      { error: "Email already exists" },
      { status: 409 }
    );
  }

  /* 📧 Send verification email */
  await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: "Auth <no-reply@medr.in>",
      to: email,
      subject: "Verify your account",
      html: `
        <p>Click the link below to verify your account:</p>
        <a href="${env.BASE_URL}/auth/verify?token=${verifyToken}">
          Verify email
        </a>
      `
    })
  });

  return Response.json({ success: true });
}
