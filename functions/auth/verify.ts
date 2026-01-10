export async function onRequest({ request, env }) {
  const token = new URL(request.url).searchParams.get("token");

  if (!token) return new Response("Invalid token", { status: 400 });

  await env.DB.prepare(
    "UPDATE users SET verified = 1, verify_token = NULL WHERE verify_token = ?"
  ).bind(token).run();

  return Response.redirect(env.BASE_URL + "/login.html", 302);
}
