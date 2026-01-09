export async function onRequest({ env }) {
  if (!env.GOOGLE_CLIENT_ID) {
    return new Response("Missing GOOGLE_CLIENT_ID", { status: 400 });
  }

  if (!env.BASE_URL) {
    return new Response("Missing BASE_URL", { status: 400 });
  }

  const redirectUri = env.BASE_URL + "/auth/callback";

  const url =
    "https://accounts.google.com/o/oauth2/v2/auth" +
    "?client_id=" + env.GOOGLE_CLIENT_ID +
    "&redirect_uri=" + encodeURIComponent(redirectUri) +
    "&response_type=code" +
    "&scope=" + encodeURIComponent("openid email profile");

  return Response.redirect(url, 302);
}
