const enc = new TextEncoder();

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

export async function onRequestPost({ request, env }) {
  const headers = { "Content-Type": "application/json" };

  try {
    const { token, password } = await request.json();
    if (!token || !password) {
      return new Response(
        JSON.stringify({ error: "Invalid request" }),
        { status: 400, headers }
      );
    }

    const user = await env.DB.prepare(
      `SELECT id, reset_expires
       FROM users WHERE reset_token=?`
    ).bind(token).first();

    if (!user || user.reset_expires < Date.now()) {
      return new Response(
        JSON.stringify({ error: "Invalid or expired token" }),
        { status: 400, headers }
      );
    }

    const { hash, salt } = await pbkdf2Hash(password);

    await env.DB.prepare(
      `
      UPDATE users
      SET password_pbkdf2=?,
          password_salt=?,
          reset_token=NULL,
          reset_expires=NULL
      WHERE id=?
      `
    ).bind(hash, salt, user.id).run();

    return new Response(
      JSON.stringify({ success: true }),
      { headers }
    );

  } catch (err) {
    console.error("RESET ERROR:", err);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers }
    );
  }
}
