export async function onRequestPost() {
  return new Response(
    JSON.stringify({ hit: true }),
    { headers: { "Content-Type": "application/json" } }
  );
}
