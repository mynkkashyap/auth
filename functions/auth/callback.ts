export async function onRequest({ request, env }) {
  const url = new URL(request.url);

  /* ------------------ 1. Read authorization code ------------------ */
  const code = url.searchParams.get("code");
  if (!code) {
    return new Response("Missing authorization code", { status: 400 });
  }

  /* ------------------ 2. Exchange code for token ------------------ */
  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: "https://auth.medr.in/auth/callback",
      grant_type: "authorization_code",
    }),
  });

  if (!tokenRes.ok) {
    const err = await tokenRes.text();
    return new Response("Token exchange failed: " + err, { status: 400 });
  }

  const token = await tokenRes.json();
  if (!token.access_token) {
    return new Response("No access token returned", { status: 400 });
  }

  /* ------------------ 3. Fetch Google user info ------------------ */
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

  /* ------------------ 4. Ensure user exists ------------------ */
  let user = await env.DB.prepare(
    "SELECT id, provider FROM users WHERE email = ?"
  )
    .bind(userInfo.email)
    .first();

  // Create user if not exists
  if (!user) {
    const result = await env.DB.prepare(
      `
      INSERT INTO users (email, name, provider, verified)
      VALUES (?, ?, 'google', 1)
      `
    )
      .bind(userInfo.email, userInfo.name ?? "")
      .run();

    user = { id: result.meta.last_row_id };
  }

  // Absolute safety check
  if (!user || !user.id) {
    return new Response("User creation failed", { status: 500 });
  }

  /* ------------------ 5. Create session ------------------ */
  const sessionId = crypto.randomUUID();
  const expiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

  await env.DB.prepare(
    "INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)"
  )
    .bind(sessionId, user.id, expiresAt)
    .run();

  /* ------------------ 6. Set cookie & redirect ------------------ */
  return new Response(null, {
    status: 302,
    headers: {
      "Set-Cookie": `session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`,
      "Location": "/dashboard.html",
    },
  });
}
