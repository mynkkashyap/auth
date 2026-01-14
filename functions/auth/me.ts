export async function onRequest({ request, env }) {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  };

  /* ------------------ Read session cookie ------------------ */
  const cookie = request.headers.get("Cookie") || "";
  const sessionId = cookie.match(/(?:^|;\s*)session=([^;]+)/)?.[1];

  if (!sessionId) {
    return new Response(
      JSON.stringify({ loggedIn: false }),
      { status: 401, headers }
    );
  }

  /* ------------------ Validate session ------------------ */
  const now = Math.floor(Date.now() / 1000); // ✅ seconds

  const session = await env.DB.prepare(
    `
    SELECT user_id
    FROM sessions
    WHERE id = ?
      AND expires_at > ?
    `
  )
    .bind(sessionId, now)
    .first();

  if (!session) {
    return new Response(
      JSON.stringify({ loggedIn: false }),
      { status: 401, headers }
    );
  }

  /* ------------------ Fetch user profile ------------------ */
  const user = await env.DB.prepare(
    `
    SELECT
      email,
      name,
      bio,
      gender,
      age,
      instagram,
      mobile,
      twitter,
      provider
    FROM users
    WHERE id = ?
    `
  )
    .bind(session.user_id)
    .first();

  if (!user) {
    // Extremely rare edge case (deleted user)
    return new Response(
      JSON.stringify({ loggedIn: false }),
      { status: 401, headers }
    );
  }

  /* ------------------ Success ------------------ */
  return new Response(
    JSON.stringify({
      loggedIn: true,
      user,
    }),
    { status: 200, headers }
  );
}
