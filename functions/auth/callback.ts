export async function onRequest({ request, env }) {
  const url = new URL(request.url);

  // Handle Google OAuth errors
  const error = url.searchParams.get("error");
  if (error) {
    return new Response("Google OAuth error: " + error, { status: 400 });
  }

  const code = url.searchParams.get("code");
  if (!code) {
    return new Response("Missing authorization code", { status: 400 });
  }

  // 🔁 Exchange authorization code for access token
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: `${env.BASE_URL}/auth/callback`,
      grant_type: "authorization_code",
    }),
  });

  if (!tokenRes.ok) {
    const err = await tokenRes.text();
    return new Response("Token exchange failed: " + err, { status: 400 });
  }

  const token = await tokenRes.json();

  if (!token.access_token) {
    return new Response(
      "No access token returned: " + JSON.stringify(token),
      { status: 400 }
    );
  }

  // 👤 Fetch Google user info
  const userInfoRes = await fetch(
    "https://www.googleapis.com/oauth2/v2/userinfo",
    {
      headers: {
        Authorization: `Bearer ${token.access_token}`,
      },
    }
  );

  if (!userInfoRes.ok) {
    return new Response("Failed to fetch user info", { status: 400 });
  }

  const userInfo = await userInfoRes.json();

  if (!userInfo.email) {
    return new Response("Google account has no email", { status: 400 });
  }

  // 🧾 Insert user if not exists
  await env.DB.prepare(
    "INSERT OR IGNORE INTO users (email, name, provider) VALUES (?, ?, 'google')"
  )
    .bind(userInfo.email, userInfo.name ?? "")
    .run();

  // 🔍 Fetch user ID
  const user = await env.DB.prepare(
    "SELECT id FROM users WHERE email = ?"
  )
    .bind(userInfo.email)
    .first();

  if (!user) {
    return new Response("User creation failed", { status: 500 });
  }

  // 🔑 Create session
  const sessionId = crypto.randomUUID();
  const expiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

  await env.DB.prepare(
    "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
  )
    .bind(sessionId, user.id, expiresAt)
    .run();

  // 🍪 Set secure cookie and redirect
  return new Response(null, {
    status: 302,
    headers: {
      "Set-Cookie": `session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`,
      "Location": `${env.BASE_URL}/dashboard.html`,
    },
  });
}
