export async function onRequest({ env }) {
  const redirectUri = env.BASE_URL + "/auth/callback";

  const url =
    "https://accounts.google.com/o/oauth2/v2/auth" +
    "?client_id=" + env.GOOGLE_CLIENT_ID +
    "&redirect_uri=" + encodeURIComponent(redirectUri) +
    "&response_type=code" +
    "&scope=" + encodeURIComponent("openid email profile") +
    "&access_type=online" +
    "&prompt=select_account";

  return Response.redirect(url, 302);
}
