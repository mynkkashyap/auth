export async function onRequestPost({ request, env }) {
  const cookie = request.headers.get("Cookie") || "";
  const sessionId = cookie.match(/session=([^;]+)/)?.[1];

  if (!sessionId) {
    return new Response(
      JSON.stringify({ error: "Unauthorized" }),
      { status: 401 }
    );
  }

  const session = await env.DB.prepare(
    "SELECT user_id FROM sessions WHERE id = ? AND expires_at > ?"
  )
    .bind(sessionId, Date.now())
    .first();

  if (!session) {
    return new Response(
      JSON.stringify({ error: "Invalid session" }),
      { status: 401 }
    );
  }

  const { name } = await request.json();

  await env.DB.prepare(
    "UPDATE users SET name = ? WHERE id = ?"
  )
    .bind(name, session.user_id)
    .run();

  return new Response(
    JSON.stringify({ success: true }),
    { headers: { "Content-Type": "application/json" } }
  );
}
