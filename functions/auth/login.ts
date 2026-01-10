async function hashPassword(password: string): Promise<string> {
  const enc = new TextEncoder();
  const data = enc.encode(password);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function onRequestPost({ request, env }) {
  const { email, password } = await request.json();

  const password_hash = await hashPassword(password);

  const user = await env.DB.prepare(
    "SELECT id FROM users WHERE email = ? AND password_hash = ?"
  )
    .bind(email, password_hash)
    .first();

  if (!user) {
    return new Response(
      JSON.stringify({ error: "Invalid credentials" }),
      { status: 401 }
    );
  }

  // 🔑 CREATE SESSION
  const sessionId = crypto.randomUUID();
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;

  await env.DB.prepare(
    "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
  )
    .bind(sessionId, user.id, expiresAt)
    .run();

  return new Response(
    JSON.stringify({ success: true }),
    {
      headers: {
        "Set-Cookie": `session=${sessionId}; HttpOnly; Secure; Path=/; SameSite=Lax`,
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
      }
    }
  );
}
