export async function onRequestPost() {
  return new Response("OK", {
    headers: {
      "Set-Cookie": "session=; Path=/; Max-Age=0"
    }
  });
}
