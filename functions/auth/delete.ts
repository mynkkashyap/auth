export async function onRequestPost({ request, env }) {
  try {
    const cookie = request.headers.get("Cookie") || "";
    const sessionId = cookie.match(/session=([^;]+)/)?.[1];

    if (!sessionId) {
      return new Response("Unauthorized", { status: 401 });
    }

    // 🔍 Find session
    const session = await env.DB.prepare(
      "SELECT user_id FROM sessions WHERE id = ?"
    ).bind(sessionId).first();

    if (!session) {
      return new Response("Invalid session", { status: 401 });
    }

    const userId = session.user_id;

    // 🔥 Delete sessions first
    await env.DB.prepare(
      "DELETE FROM sessions WHERE user_id = ?"
    ).bind(userId).run();

    // 🔥 Delete user
    await env.DB.prepare(
      "DELETE FROM users WHERE id = ?"
    ).bind(userId).run();

    // 🍪 Clear cookie
    return new Response(JSON.stringify({ success: true }), {
      headers: {
        "Set-Cookie": "session=; Path=/; HttpOnly; Max-Age=0",
        "Content-Type": "application/json"
      }
    });

  } catch (err) {
    console.error("DELETE ACCOUNT ERROR:", err);
    return new Response(
      JSON.stringify({ error: "Failed to delete account" }),
      { status: 500 }
    );
  }
}
