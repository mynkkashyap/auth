export async function onRequest({ request, env }) {
  const url = new URL(request.url);

  const error = url.searchParams.get("error");
  if (error) {
    return new Response("Google OAuth error: " + error, { status: 400 });
  }

  const code = url.searchParams.get("code");
  if (!code) {
    return new Response("Missing code", { status: 400 });
  }

  // 🔄 Exchange code for token
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: env.BASE_URL + "/auth/callback",
      grant_type: "authorization_code"
    })
  });

  const token = await tokenRes.json();

  if (!token.access_token) {
    return new Response(
      "Token exchange failed: " + JSON.stringify(token),
      { status: 400 }
    );
  }

  // 👤 Fetch Google user info
  const userInfo = await fetch(
    "https://www.googleapis.com/oauth2/v2/userinfo",
    {
      headers: {
        Authorization: `Bearer ${token.access_token}`
      }
    }
  ).then(r => r.json());

  // 🧾 Insert user if not exists
  await env.DB.prepare(
    "INSERT OR IGNORE INTO users (email, name, provider) VALUES (?, ?, 'google')"
  )
    .bind(userInfo.email, userInfo.name)
    .run();

  // 🔑 Fetch user id
  const user = await env.DB.prepare(
    "SELECT id FROM users WHERE email = ?"
  )
    .bind(userInfo.email)
    .first();

  if (!user) {
    return new Response("User creation failed", { status: 500 });
  }

  // 🔐 CREATE SESSION (MATCH LOGIN FLOW)
  const sessionId = crypto.randomUUID();
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;

  await env.DB.prepare(
    "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
  )
    .bind(sessionId, user.id, expiresAt)
    .run();

  // 🍪 SET COOKIE + REDIRECT
  return new Response(null, {
    status: 302,
    headers: {
      "Set-Cookie": `session=${sessionId}; HttpOnly; Secure; Path=/; SameSite=Lax`,
      "Location": env.BASE_URL + "/dashboard.html",
      "Cache-Control": "no-store"
    }
  });
}
