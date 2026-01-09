export async function onRequest({ env }) {
  const url =
    "https://accounts.google.com/o/oauth2/v2/auth" +
    "?client_id=" + env.GOOGLE_CLIENT_ID +
    "&redirect_uri=" + env.BASE_URL + "/auth/callback" +
    "&response_type=code" +
    "&scope=openid email profile";

  return Response.redirect(url, 302);
}
