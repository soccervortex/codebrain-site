export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors() });
    }

    const url = new URL(request.url);

    try {
      if (url.pathname === "/waitlist" && request.method === "POST") {
        return await handleWaitlist(request, env);
      }

      if (url.pathname === "/auth/register" && request.method === "POST") {
        return await handleRegister(request, env);
      }
      if (url.pathname === "/auth/me" && request.method === "GET") {
        return await handleMe(request, env);
      }

      if (url.pathname === "/auth/login" && request.method === "POST") {
        return await handleLogin(request, env);
      }

      return new Response("Not found", { status: 404 });
    } catch {
      return json({ error: "Invalid request" }, 400);
    }
  }
};

async function handleWaitlist(request, env) {
  const body = await request.json();

  if (body.website) return json({ ok: true });

  const normalized = String(body.email || "").trim().toLowerCase();

  if (!normalized.includes("@") || !normalized.includes(".")) {
    return json({ error: "Invalid email" }, 400);
  }

  const ip = request.headers.get("CF-Connecting-IP") || "unknown";

  const rate = await env.codebrain_waitlist
    .prepare(`
      SELECT COUNT(*) AS count
      FROM requests
      WHERE ip = ? AND created_at > datetime('now', '-1 hour')
    `)
    .bind(ip)
    .first();

  if (Number(rate?.count || 0) >= 5) {
    return json({ error: "Too many requests" }, 429);
  }

  await env.codebrain_waitlist
    .prepare("INSERT INTO requests (ip) VALUES (?)")
    .bind(ip)
    .run();

  await env.codebrain_waitlist
    .prepare("INSERT OR IGNORE INTO waitlist (email) VALUES (?)")
    .bind(normalized)
    .run();

  return json({ ok: true });
}

async function handleRegister(request, env) {
  const body = await request.json();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!email.includes("@") || password.length < 8) {
    return json({ error: "Invalid email or password" }, 400);
  }

  const passwordHash = await hashPassword(password);

  try {
    await env.codebrain_waitlist
      .prepare("INSERT INTO users (email, password_hash) VALUES (?, ?)")
      .bind(email, passwordHash)
      .run();
  } catch {
    return json({ error: "Account already exists" }, 409);
  }

  return json({ ok: true });
}

async function handleLogin(request, env) {
  const body = await request.json();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!email || !password) return json({ error: "Invalid credentials" }, 401);

  const user = await env.codebrain_waitlist
    .prepare("SELECT id, password_hash FROM users WHERE email = ?")
    .bind(email)
    .first();

  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return json({ error: "Invalid credentials" }, 401);
  }

  const token = toHex(crypto.getRandomValues(new Uint8Array(32)));
  const tokenHash = await sha256(token);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  await env.codebrain_waitlist.prepare("INSERT INTO sessions (user_id, token_hash, expires_at) VALUES (?, ?, ?)").bind(user.id, tokenHash, expiresAt).run();
  return new Response(JSON.stringify({ ok: true, token }), { status: 200, headers: { "Content-Type": "application/json", "Set-Cookie": `codebrain_session=${token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=604800`, ...cors() } });
}

async function handleMe(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)codebrain_session=([^;]+)/);
  if (!match) return json({ error: "Unauthorized" }, 401);

  const tokenHash = await sha256(match[1]);
  const session = await env.codebrain_waitlist
    .prepare("SELECT users.id, users.email FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = ? AND sessions.expires_at > datetime('now')")
    .bind(tokenHash)
    .first();

  if (!session) return json({ error: "Unauthorized" }, 401);
  return json({ ok: true, user_id: session.id, email: session.email });
}

async function verifyPassword(password, stored) {
  const [scheme, iterationsText, saltHex, hashHex] = String(stored).split("$");
  if (scheme !== "pbkdf2" || !iterationsText || !saltHex || !hashHex) return false;

  const salt = new Uint8Array(saltHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: Number(iterationsText), hash: "SHA-256" },
    key,
    256
  );

  return toHex(new Uint8Array(bits)) === hashHex;
}

async function sha256(value) {
  const data = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return toHex(new Uint8Array(hash));
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 10000, hash: "SHA-256" },
    key,
    256
  );
  return `pbkdf2$10000$${toHex(salt)}$${toHex(new Uint8Array(bits))}`;
}

function toHex(bytes) {
  return [...bytes].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

function cors() {
  return {
    "Access-Control-Allow-Origin": "https://soccervortex.github.io",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization", "Access-Control-Allow-Credentials": "true"
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...cors()
    }
  });
}
