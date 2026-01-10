export async function onRequestPost({ request, env }) {
  const cookie = request.headers.get("Cookie") || "";
  const sessionId = cookie.match(/session=([^;]+)/)?.[1];
  if (!sessionId) return new Response("No session", { status: 401 });

  const session = await env.DB.prepare(
    "SELECT user_id FROM sessions WHERE id = ?"
  ).bind(sessionId).first();

  if (!session) return new Response("Invalid session", { status: 401 });

  await env.DB.prepare("DELETE FROM users WHERE id = ?")
    .bind(session.user_id)
    .run();

  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?")
    .bind(session.user_id)
    .run();

  return new Response("Deleted", {
    headers: {
      "Set-Cookie": "session=; Max-Age=0; Path=/"
    }
  });
}
