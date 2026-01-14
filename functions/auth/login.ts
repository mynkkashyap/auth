const enc = new TextEncoder();

/* 🔐 SHA-256 (legacy - for migration only) */
async function sha256(password: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(password));
  return [...new Uint8Array(hash)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

/* 🔐 PBKDF2 Hash Function */
async function pbkdf2Hash(password: string, salt?: Uint8Array): Promise<{ hash: string, salt: string }> {
  salt = salt || crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { 
      name: "PBKDF2", 
      salt, 
      iterations: 100_000, 
      hash: "SHA-256" 
    },
    key,
    256
  );

  return {
    hash: [...new Uint8Array(bits)]
      .map(b => b.toString(16).padStart(2, "0"))
      .join(""),
    salt: [...salt]
      .map(b => b.toString(16).padStart(2, "0"))
      .join("")
  };
}

/* 🔐 PBKDF2 Verify Function */
async function pbkdf2Verify(
  password: string,
  storedHash: string,
  saltHex: string
): Promise<boolean> {
  const salt = Uint8Array.from(
    saltHex.match(/.{1,2}/g)!.map(b => parseInt(b, 16))
  );
  
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { 
      name: "PBKDF2", 
      salt, 
      iterations: 100_000, 
      hash: "SHA-256" 
    },
    key,
    256
  );

  const computedHash = [...new Uint8Array(bits)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
    
  return computedHash === storedHash;
}

export async function onRequestPost({ request, env }) {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  };

  try {
    const body = await request.json();
    const { email, password, recaptchaToken } = body;
    
    // Get reCAPTCHA token from body or header
    const token = recaptchaToken || request.headers.get("X-Recaptcha-Token");
    
    if (!token) {
      return new Response(
        JSON.stringify({ error: "Missing reCAPTCHA token" }),
        { status: 400, headers }
      );
    }

    /* ------------------ Verify reCAPTCHA ------------------ */
    const googleRes = await fetch(
      "https://www.google.com/recaptcha/api/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          secret: env.RECAPTCHA_SECRET_KEY,
          response: token,
        }),
      }
    );

    const captcha = await googleRes.json();

    if (!captcha.success || captcha.score < 0.5) {
      console.warn("reCAPTCHA failed:", {
        success: captcha.success,
        score: captcha.score,
        errors: captcha["error-codes"]
      });
      return new Response(
        JSON.stringify({ error: "Security check failed. Please try again." }),
        { status: 403, headers }
      );
    }

    /* ------------------ Validate Input ------------------ */
    if (!email || !email.trim()) {
      return new Response(
        JSON.stringify({ error: "Email is required" }),
        { status: 400, headers }
      );
    }

    if (!password || !password.trim()) {
      return new Response(
        JSON.stringify({ error: "Password is required" }),
        { status: 400, headers }
      );
    }

    const normalizedEmail = email.toLowerCase().trim();

    /* ------------------ Database Lookup ------------------ */
    const user = await env.DB.prepare(`
      SELECT
        id,
        provider,
        verified,
        password_hash,
        password_pbkdf2,
        password_salt
      FROM users
      WHERE email = ?
    `).bind(normalizedEmail).first();

    // Use generic error message for security (don't reveal if user exists)
    if (!user) {
      // Optional: Add delay to prevent timing attacks
      await new Promise(resolve => setTimeout(resolve, 500));
      return new Response(
        JSON.stringify({ error: "Invalid email or password" }),
        { status: 401, headers }
      );
    }

    /* 🚫 BLOCK GOOGLE OAUTH USERS ------------------ */
    if (user.provider === "google") {
      return new Response(
        JSON.stringify({ 
          error: "Please use Google Sign-In for this account",
          provider: "google" 
        }),
        { status: 409, headers }
      );
    }

    /* 🚫 CHECK EMAIL VERIFICATION ------------------ */
    if (user.verified !== 1) {
      return new Response(
        JSON.stringify({ 
          error: "Please verify your email address before logging in",
          needsVerification: true 
        }),
        { status: 403, headers }
      );
    }

    /* ------------------ PASSWORD VERIFICATION ------------------ */
    let passwordValid = false;

    // Priority 1: Check PBKDF2 (modern)
    if (user.password_pbkdf2 && user.password_salt) {
      passwordValid = await pbkdf2Verify(
        password,
        user.password_pbkdf2,
        user.password_salt
      );
    } 
    // Priority 2: Check SHA-256 (legacy - migrate to PBKDF2)
    else if (user.password_hash) {
      passwordValid = (await sha256(password)) === user.password_hash;

      // If password is valid, migrate to PBKDF2
      if (passwordValid) {
        const { hash, salt } = await pbkdf2Hash(password);
        await env.DB.prepare(`
          UPDATE users
          SET password_pbkdf2 = ?, password_salt = ?, password_hash = NULL
          WHERE id = ?
        `).bind(hash, salt, user.id).run();
        
        console.log(`Migrated user ${user.id} from SHA256 to PBKDF2`);
      }
    }
    // No password method found (shouldn't happen)
    else {
      console.error(`User ${user.id} has no password method configured`);
      return new Response(
        JSON.stringify({ error: "Account configuration error" }),
        { status: 500, headers }
      );
    }

    if (!passwordValid) {
      // Optional: Track failed login attempts
      await env.DB.prepare(`
        UPDATE users 
        SET failed_attempts = COALESCE(failed_attempts, 0) + 1,
            last_failed_attempt = ?
        WHERE id = ?
      `).bind(Date.now(), user.id).run();
      
      return new Response(
        JSON.stringify({ error: "Invalid email or password" }),
        { status: 401, headers }
      );
    }

    /* ------------------ CREATE SESSION ------------------ */
    // Reset failed attempts on successful login
    await env.DB.prepare(`
      UPDATE users 
      SET failed_attempts = 0, last_login = ?
      WHERE id = ?
    `).bind(Date.now(), user.id).run();

    // Generate session ID
    const sessionId = crypto.randomUUID();
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days
    
    // Store session in database
    await env.DB.prepare(`
      INSERT INTO sessions (id, user_id, expires_at, created_at)
      VALUES (?, ?, ?, ?)
    `).bind(
      sessionId,
      user.id,
      Math.floor(expiresAt / 1000), // Store as Unix timestamp (seconds)
      Math.floor(Date.now() / 1000)
    ).run();

    /* ------------------ PREPARE RESPONSE ------------------ */
    const responseData = {
      success: true,
      message: "Login successful",
      redirectUrl: "/dashboard",
      user: {
        id: user.id,
        email: normalizedEmail
      }
    };

    // Create secure cookie
    const cookie = [
      `session=${sessionId}`,
      "HttpOnly",
      "Secure",
      "Path=/",
      "SameSite=Lax",
      `Max-Age=${7 * 24 * 60 * 60}` // 7 days in seconds
    ].join("; ");

    return new Response(
      JSON.stringify(responseData),
      {
        status: 200,
        headers: {
          ...headers,
          "Set-Cookie": cookie,
        },
      }
    );

  } catch (error) {
    console.error("LOGIN ERROR:", error);
    
    // Don't expose internal errors to client
    return new Response(
      JSON.stringify({ error: "An unexpected error occurred. Please try again." }),
      { status: 500, headers }
    );
  }
}


  
