export async function onRequest({ env }) {
  const url =
    "https://accounts.google.com/o/oauth2/v2/auth" +
    "?client_id=" + env.662047030240-ndto429qnhd8sc8rr3ennlbv17bqg2h7.apps.googleusercontent.com +
    "&redirect_uri=" + env.auth.pages.dev + "/auth/callback" +
    "&response_type=code" +
    "&scope=openid email profile";
  return Response.redirect(url, 302);
}
