export async function onRequestGet({ env }) {
  const { results } = await env.DB
    .prepare(`
      SELECT id, name, email
      FROM users
      WHERE verified = 1
      ORDER BY id DESC
    `)
    .all();

  return new Response(JSON.stringify(results), {
    headers: { "Content-Type": "application/json" },
  });
}
