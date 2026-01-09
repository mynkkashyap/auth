export async function onRequest({ request, env, next }) {
  const cookie = request.headers.get("Cookie") || "";
  const session = cookie.match(/session=([^;]+)/)?.[1];
  if (request.url.includes("/dashboard") && !session) {
    return Response.redirect(env.BASE_URL + "/login.html", 302);
  }
  return next();
}