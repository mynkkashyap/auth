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
    "SELECT * FROM users WHERE email = ? AND password_hash = ?"
  )
    .bind(email, password_hash)
    .first();

  if (!user) {
    return new Response("Invalid credentials", { status: 401 });
  }

  const sessionId = crypto.randomUUID();

  await env.DB.prepare(
    "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
  )
    .bind(sessionId, user.id, Date.now() + 86400000)
    .run();

  return new Response("OK", {
    headers: {
      "Set-Cookie": `session=${sessionId}; HttpOnly; Secure; Path=/; SameSite=Lax`
    }
  });
}
