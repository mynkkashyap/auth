// GET request (browser visit)
export async function onRequestGet() {
  return new Response(
    "This endpoint only accepts POST requests",
    { status: 405 }
  );
}

// POST request (actual registration)
export async function onRequestPost({ request, env }) {
  if (!env.DB) {
    return new Response(
      JSON.stringify({ error: "DB binding missing" }),
      { status: 500 }
    );
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(
      JSON.stringify({ error: "Invalid JSON" }),
      { status: 400 }
    );
  }

  const { email, password, name } = body;

  if (!email || !password) {
    return new Response(
      JSON.stringify({ error: "Missing email or password" }),
      { status: 400 }
    );
  }

  // Hash password (Cloudflare-safe)
  const enc = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    enc.encode(password)
  );
  const password_hash = [...new Uint8Array(hashBuffer)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  try {
    await env.DB.prepare(
      "INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)"
    )
      .bind(email, name ?? "", password_hash)
      .run();
  } catch (e) {
    return new Response(
      JSON.stringify({ error: "Email already exists" }),
      { status: 409 }
    );
  }

  return new Response(
    JSON.stringify({ success: true }),
    { headers: { "Content-Type": "application/json" } }
  );
}
