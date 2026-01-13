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
    name,
    bio,
    gender,
    age,
    mobile,
    instagram,
    twitter
  } = await request.json();

  if (!name || !name.trim()) {
    return new Response("Empty name", { status: 400 });
  }

  const parsedAge =
    age !== undefined && age !== null && age !== ""
      ? Number.isInteger(Number(age)) ? Number(age) : null
      : null;

  if (parsedAge !== null && (parsedAge < 1 || parsedAge > 120)) {
    return new Response("Invalid age", { status: 400 });
  }

  const result = await env.DB.prepare(`
    UPDATE users
    SET
      name = ?,
      bio = ?,
      gender = ?,
      age = ?,
      mobile = ?,
      instagram = ?,
      twitter = ?,
      updated_at = ?
    WHERE id = ?
  `).bind(
    name.trim(),
    bio || null,
    gender || null,
    parsedAge,
    mobile || null,
    instagram || null,
    twitter || null,
    Math.floor(Date.now() / 1000),
    session.user_id
  ).run();

  return new Response(
    JSON.stringify({ updated: result.meta.changes }),
    { headers: { "Content-Type": "application/json" } }
  );
}
