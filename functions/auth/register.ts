import bcrypt from "bcryptjs";

export async function onRequestPost({ request, env }) {
  const { email, password, name } = await request.json();
  const hash = await bcrypt.hash(password, 10);
  await env.DB.prepare(
    "INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)"
  ).bind(email, name, hash).run();
  return new Response(JSON.stringify({ success: true }), { status: 200 });
}