import bcrypt from "bcryptjs";
import { nanoid } from "nanoid";

export async function onRequestPost({ request, env }) {
  const { email, password } = await request.json();
  const user = await env.DB.prepare(
    "SELECT * FROM users WHERE email = ?"
  ).bind(email).first();

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return new Response("Invalid credentials", { status: 401 });
  }

  const sessionId = nanoid();
  await env.DB.prepare(
    "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
  ).bind(sessionId, user.id, Date.now() + 86400000).run();

  return new Response("OK", {
    headers: {
      "Set-Cookie": `session=${sessionId}; HttpOnly; Secure; Path=/; SameSite=Lax`
    }
  });
}