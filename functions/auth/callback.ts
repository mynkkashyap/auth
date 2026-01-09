export async function onRequest({ request, env }) {
  const code = new URL(request.url).searchParams.get("code");
  if (!code) {
    return new Response("Missing code", { status: 400 });
  }

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

  const userInfo = await fetch(
    "https://www.googleapis.com/oauth2/v2/userinfo",
    {
      headers: {
        Authorization: `Bearer ${token.access_token}`
      }
    }
  ).then(r => r.json());

  await env.DB.prepare(
    "INSERT OR IGNORE INTO users (email, name, provider) VALUES (?, ?, 'google')"
  )
    .bind(userInfo.email, userInfo.name)
    .run();

  return Response.redirect(env.BASE_URL + "/dashboard.html", 302);
}
