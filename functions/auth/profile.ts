export async function onRequestPost({ request, env }) {
  if (!env.DB) {
    return new Response(
      JSON.stringify({ error: "DB binding missing" }),
      { status: 500 }
    );
  }

  // 🔐 Read session cookie
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/session=([^;]+)/);

  if (!match) {
    return new Response(
      JSON.stringify({ error: "No session cookie" }),
      { status: 401 }
    );
  }

  const sessionId = match[1];

  // 🔍 Validate session
  const session = await env.DB.prepare(
    "SELECT user_id FROM sessions WHERE id = ? AND expires_at > ?"
  )
    .bind(sessionId, Date.now())
    .first();

  if (!session || !session.user_id) {
    return new Response(
      JSON.stringify({ error: "Invalid session" }),
      { status: 401 }
    );
  }

  // 📦 Parse request
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(
      JSON.stringify({ error: "Invalid JSON body" }),
      { status: 400 }
    );
  }

  const { name } = body;

  if (!name || name.trim().length < 2) {
    return new Response(
      JSON.stringify({ error: "Name too short" }),
      { status: 400 }
    );
  }

  // ✅ UPDATE USER
  const result = await env.DB.prepare(
    "UPDATE users SET name = ? WHERE id = ?"
  )
    .bind(name.trim(), session.user_id)
    .run();

  return new Response(
    JSON.stringify({
      success: true,
      rowsAffected: result.meta.changes
    }),
    {
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
      }
    }
  );
}
