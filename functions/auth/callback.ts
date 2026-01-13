export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");

  if (!code) return new Response("Missing authorization code", { status: 400 });

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: "https://auth.medr.in/auth/callback",
      grant_type: "authorization_code"
    })
  });

  if (!tokenRes.ok) return new Response(await tokenRes.text(), { status: 400 });
  const token = await tokenRes.json();

  const userInfo = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
    headers: { Authorization: `Bearer ${token.access_token}` }
  }).then(r => r.json());

  await env.DB.prepare(
    "INSERT OR IGNORE INTO users (email,name,provider,verified) VALUES (?,?,'google',1)"
  ).bind(userInfo.email, userInfo.name).run();

  const user = await env.DB.prepare(
    "SELECT id FROM users WHERE email=?"
  ).bind(userInfo.email).first();

  const sessionId = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO sessions (id,user_id,expires_at) VALUES (?,?,?)"
  ).bind(sessionId, user.id, Date.now() + 864e5).run();

  return new Response(null, {
    status: 302,
    headers: {
      "Set-Cookie": `session=${sessionId}; HttpOnly; Secure; Path=/; SameSite=Lax`,
      "Location": "/dashboard.html"
    }
  });
}
