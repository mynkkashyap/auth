export async function onRequest({ request, env }) {
  const cookie = request.headers.get("Cookie") || "";
  const sessionId = cookie.match(/session=([^;]+)/)?.[1];

  if (!sessionId) {
    return new Response(
      JSON.stringify({ loggedIn: false }),
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
      JSON.stringify({ loggedIn: false }),
      { status: 401 }
    );
  }

  // 🔑 INCLUDE provider HERE
  const user = await env.DB.prepare(
    "SELECT email, name, bio, gender, message, instagram, mobile, twitter, provider FROM users WHERE id = ?"
  )
    .bind(session.user_id)
    .first();

  return new Response(
  JSON.stringify({
    loggedIn: true,
    user
  }),
  {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  }
);
}
