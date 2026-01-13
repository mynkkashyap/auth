export async function onRequest({ env }) {
  const redirectUri = "https://auth.medr.in/auth/callback";

  const url =
    "https://accounts.google.com/o/oauth2/v2/auth?" +
    new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "openid email profile",
      prompt: "select_account"
    });

  return Response.redirect(url, 302);
}
