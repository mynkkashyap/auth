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

  /* ------------------ 4. Ensure user exists / link account ------------------ */
  let user = await env.DB.prepare(
    `
    SELECT id, provider, verified, google_linked
    FROM users
    WHERE email = ?
    `
  )
    .bind(userInfo.email)
    .first();

  /* 🆕 Case 1: Brand-new Google user */
  if (!user) {
    const userId = crypto.randomUUID();

    await env.DB.prepare(
      `
      INSERT INTO users (
        id, email, name, provider, verified, google_linked
      )
      VALUES (?, ?, ?, 'google', 1, 1)
      `
    )
      .bind(
        userId,
        userInfo.email,
        userInfo.name ?? ""
      )
      .run();

    user = { id: userId };
  }

  /* 🔁 Case 2: Existing email user → link Google */
  else if (user.provider === "email") {
    if (user.verified !== 1) {
      return new Response(
        "Verify email before using Google Sign-In",
        { status: 403 }
      );
    }

    if (!user.google_linked) {
      await env.DB.prepare(
        "UPDATE users SET google_linked = 1 WHERE id = ?"
      )
        .bind(user.id)
        .run();
    }
  }

  /* ------------------ 5. Create session ------------------ */
  const sessionId = crypto.randomUUID();
  const expiresAt = Date.now() + 24 * 60 * 60 * 1000;

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
