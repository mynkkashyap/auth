async function hashPassword(password: string): Promise<string> {
  const enc = new TextEncoder();
  const data = enc.encode(password);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function onRequestPost({ request, env }) {
  const { email, password, name } = await request.json();

  const password_hash = await hashPassword(password);

  await env.DB.prepare(
    "INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)"
  )
    .bind(email, name, password_hash)
    .run();

  return new Response(JSON.stringify({ success: true }), {
    headers: { "Content-Type": "application/json" }
  });
}
