export async function onRequestPost({ request, env }) {
  const cookie = request.headers.get("Cookie") || "";
  const sessionId = cookie.match(/session=([^;]+)/)?.[1];
  if (!sessionId) {
    return new Response("No session", { status: 401 });
  }

  const session = await env.DB.prepare(
    "SELECT user_id FROM sessions WHERE id = ?"
  ).bind(sessionId).first();

  if (!session) {
    return new Response("Invalid session", { status: 401 });
  }

  const {
    updated_at,
    created_at,
    name,
    bio,
    gender,
    age,
    mobile,
    instagram,
    twitter
  } = await request.json();

  if (!name) {
    return new Response("Empty name", { status: 400 });
  }

  const parsedAge = age ? parseInt(age, 10) : null;

  const result = await env.DB.prepare(`
    UPDATE users
    SET
      name = ?,
      bio = ?,
      gender = ?,
      age = ?,
      mobile = ?,
      instagram = ?,
      twitter = ?
    WHERE id = ?
  `).bind(
    name,
    bio || null,
    gender || null,
    parsedAge,
    mobile || null,
    instagram || null,
    twitter || null,
    session.user_id
  ).run();

  return new Response(
    JSON.stringify({ updated: result.meta.changes }),
    {
      headers: { "Content-Type": "application/json" }
    }
  );
}
