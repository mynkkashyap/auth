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
          <!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Your Password</title>
  <style>
    /* Client-specific resets */
    body, table, td, a { -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }
    table, td { mso-table-lspace: 0pt; mso-table-rspace: 0pt; }
    img { -ms-interpolation-mode: bicubic; }
    
    /* General styles */
    body { margin: 0; padding: 0; background-color: #f4f4f7; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; }
    
    /* Button Hover */
    .btn:hover { background-color: #0056b3 !important; }
  </style>
</head>
<body style="margin: 0; padding: 0; background-color: #f4f4f7; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;">

  <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f4f4f7; padding: 20px 0;">
    <tr>
      <td align="center">
        
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden;">
          
          <tr>
            <td align="center" style="padding: 30px 20px 20px 20px; background-color: #ffffff; border-bottom: 1px solid #eeeeee;">
              <h1 style="margin: 0; font-size: 24px; color: #333333; font-weight: bold;">Account Security</h1>
            </td>
          </tr>

          <tr>
            <td style="padding: 40px 30px;">
              <p style="margin: 0 0 20px 0; font-size: 16px; line-height: 24px; color: #555555;">
                Hello,
              </p>
              <p style="margin: 0 0 30px 0; font-size: 16px; line-height: 24px; color: #555555;">
                We received a request to reset the password for your account. If you didn't make this request, you can safely ignore this email.
              </p>

              <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                  <td align="center">
                    <a href="${env.BASE_URL}/reset.html?token=${token}" class="btn" style="display: inline-block; padding: 14px 30px; background-color: #007bff; color: #ffffff; text-decoration: none; border-radius: 5px; font-weight: bold; font-size: 16px; text-align: center;">
                      Reset Password
                    </a>
                  </td>
                </tr>
              </table>

              <p style="margin: 30px 0 0 0; font-size: 14px; line-height: 20px; color: #888888; text-align: center;">
                For security reasons, this link expires in <strong>30 minutes</strong>.
              </p>
            </td>
          </tr>

          <tr>
            <td style="background-color: #f9f9f9; padding: 20px; text-align: center; border-top: 1px solid #eeeeee;">
              <p style="margin: 0; font-size: 12px; line-height: 18px; color: #999999;">
                If the button above doesn't work, copy and paste the following link into your browser:<br>
                <a href="${env.BASE_URL}/reset.html?token=${token}" style="color: #007bff; text-decoration: underline; word-break: break-all;">
                  ${env.BASE_URL}/reset.html?token=${token}
                </a>
              </p>
            </td>
          </tr>
          
        </table>
        
        <p style="margin-top: 20px; font-size: 12px; color: #999999; text-align: center;">
          &copy; ${new Date().getFullYear()} Your Company Name. All rights reserved.
        </p>

      </td>
    </tr>
  </table>

</body>
</html>

        `
      })
    });

    return new Response(JSON.stringify({ success: true }), { headers });

  } catch (err) {
    console.error("FORGOT ERROR:", err);
    return new Response(JSON.stringify({ success: true }), { headers });
  }
}
