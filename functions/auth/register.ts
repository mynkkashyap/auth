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
    hash: [...new Uint8Array(bits)]
      .map(b => b.toString(16).padStart(2, "0"))
      .join(""),
    salt: [...salt]
      .map(b => b.toString(16).padStart(2, "0"))
      .join("")
  };
}

/* 🔑 Verification token */
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
      throw new Error("Missing environment variables");
    }

    const body = await request.json();
    const { name = "", email, password } = body;

    if (!email || !password) {
      return new Response(
        JSON.stringify({ error: "Missing email or password" }),
        { status: 400, headers }
      );
    }

    const normalizedEmail = email.toLowerCase().trim();

    /* 🔐 Hash password */
    const { hash, salt } = await pbkdf2Hash(password);
    const verifyToken = generateToken();

    /* 🧾 Insert user */
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
        normalizedEmail,
        hash,
        salt,
        verifyToken
      )
      .run();

    /* 📧 Send verification email */
    const emailRes = await fetch("https://api.resend.com/emails", {
  method: "POST",
  headers: {
    Authorization: `Bearer ${env.RESEND_API_KEY}`,
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    from: "Auth <onboarding@resend.dev>",
    to: normalizedEmail,
    subject: "Verify your account",
    html: `
      <p>Verify your account:</p>
      <a href="${env.BASE_URL}/auth/verify?token=${verifyToken}">
        Verify Email
      </a>
    `
  })
});

const bodyText = await emailRes.text();

console.log("RESEND STATUS:", emailRes.status);
console.log("RESEND RESPONSE:", bodyText);

if (!emailRes.ok) {
  return Response.json(
    { error: "Failed to send verification email" },
    { status: 500 }
  );
}
    if (!emailRes.ok) {
      const errText = await emailRes.text();
      console.error("EMAIL SEND FAILED:", errText);

      return new Response(
        JSON.stringify({ error: "Failed to send verification email" }),
        { status: 500, headers }
      );
    }

    return new Response(
      JSON.stringify({ success: true }),
      { headers }
    );

  } catch (err: any) {
    console.error("REGISTER ERROR:", err?.message || err);

    if (String(err).includes("UNIQUE")) {
      return new Response(
        JSON.stringify({ error: "Email already exists" }),
        { status: 409, headers }
      );
    }

    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers }
    );
  }
}
