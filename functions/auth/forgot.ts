export async function onRequestPost({ request, env }) {
  const headers = { "Content-Type": "application/json" };

  try {
    const { email } = await request.json();
    if (!email) {
      return new Response(JSON.stringify({ success: true }), { headers });
    }

    const normalizedEmail = email.toLowerCase().trim();

    const user = await env.DB.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).bind(normalizedEmail).first();

    // 🔐 Always respond success (security)
    if (!user) {
      return new Response(JSON.stringify({ success: true }), { headers });
    }

    const token = crypto.randomUUID().replace(/-/g, "");
    const expires = Date.now() + 30 * 60 * 1000; // 30 min

    await env.DB.prepare(
      `UPDATE users
       SET reset_token=?, reset_expires=?
       WHERE id=?`
    ).bind(token, expires, user.id).run();

    // 📧 Send email
    await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: "Auth <onboarding@auth.medr.in>",
        to: normalizedEmail,
        subject: "Reset your password",
        html: `
          <p>Click the link below to reset your password:</p>
          <a href="${env.BASE_URL}/reset.html?token=${token}">
            Reset Password
          </a>
          <p>This link expires in 30 minutes.</p>
        `
      })
    });

    return new Response(JSON.stringify({ success: true }), { headers });

  } catch (err) {
    console.error("FORGOT ERROR:", err);
    return new Response(JSON.stringify({ success: true }), { headers });
  }
}
