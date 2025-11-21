// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");

const app = express();

/* ============================================================
   CORS – minden origin engedélyezése
   ============================================================ */
// Mivel NINCS cookie / credentials használva, ez teljesen biztonságos
app.use(cors());
app.options("*", cors());

app.use(express.json());

/* ============================================================
   In-memory DEV store (MVP-hez). Prod: adatbázis!
   ============================================================ */
const deviceCodes = new Map(); 
const sessions = new Map();

/* ============================================================
   Helpers
   ============================================================ */
function genDeviceCode(len = 12) {
  const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
  const raw = Array.from({ length: len }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join("");
  return `${raw.slice(0,4)}-${raw.slice(4,8)}-${raw.slice(8)}`;
}

function genSessionToken() {
  return "sess_" + (Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2));
}

function resolveDiscordTokenFromAuthHeader(authorization) {
  const tok = (authorization || "").startsWith("Bearer ") ? authorization.slice(7) : "";
  if (!tok) return null;
  const sess = sessions.get(tok);
  if (sess && sess.exp > Date.now()) return sess.discord_access_token;
  return tok;
}

/* ============================================================
   Health
   ============================================================ */
app.get("/api/health", (_req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

/* ============================================================
   OAuth token csere + user lekérés
   ============================================================ */
app.post("/api/auth/discord", async (req, res) => {
  try {
    const { code, redirect_uri } = req.body || {};
    if (!code) return res.status(400).json({ error: "missing_code" });

    const redirectUri = redirect_uri || process.env.DISCORD_REDIRECT_URI;

    const params = new URLSearchParams({
      client_id: process.env.DISCORD_CLIENT_ID,
      client_secret: process.env.DISCORD_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
    });

    const tokenResp = await _fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });

    const tokenData = await tokenResp.json();
    if (!tokenResp.ok) {
      console.error("TOKEN EXCHANGE FAILED:", tokenResp.status, tokenData);
      return res.status(400).json({ error: "token_exchange_failed", details: tokenData });
    }

    const userResp = await _fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const user = await userResp.json();

    if (!user || !user.id) {
      console.error("USER FETCH FAILED:", userResp.status, user);
      return res.status(400).json({ error: "user_fetch_failed", details: user });
    }

    return res.json({
      user: {
        id: user.id,
        username: user.username,
        global_name: user.global_name,
        avatar: user.avatar,
        email: user.email,
      },
      oauth: { scope: tokenData.scope, token_type: tokenData.token_type },
      access_token: tokenData.access_token,
    });
  } catch (e) {
    console.error("SERVER ERROR (/api/auth/discord):", e);
    res.status(500).json({ error: "server_error" });
  }
});

/* ============================================================
   Device pairing
   ============================================================ */
app.post("/api/device/start", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";
    const discordToken = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!discordToken) return res.status(401).json({ error: "missing_bearer_token" });

    const meR = await _fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${discordToken}` },
    });
    const meTxt = await meR.text();
    if (!meR.ok) return res.status(401).json({ error: "discord_unauthorized", details: meTxt });
    const me = JSON.parse(meTxt);

    const code = genDeviceCode(12);
    const exp = Date.now() + 10 * 60 * 1000;

    deviceCodes.set(code, { userId: me.id, discord_access_token: discordToken, exp, used: false });

    return res.json({ device_code: code, expires_at: exp });
  } catch (e) {
    console.error("DEVICE START ERROR:", e);
    return res.status(500).json({ error: "server_error" });
  }
});

app.post("/api/device/claim", async (req, res) => {
  try {
    const { device_code, device_name } = req.body || {};
    if (!device_code) return res.status(400).json({ error: "missing_code" });

    const row = deviceCodes.get(device_code);
    if (!row) return res.status(400).json({ error: "invalid_code" });
    if (row.used) return res.status(400).json({ error: "already_used" });
    if (row.exp < Date.now()) return res.status(400).json({ error: "expired" });

    const meR = await _fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${row.discord_access_token}` },
    });
    const meTxt = await meR.text();
    if (!meR.ok) return res.status(401).json({ error: "discord_unauthorized", details: meTxt });
    const me = JSON.parse(meTxt);

    row.used = true;
    const session_token = genSessionToken();
    const exp = Date.now() + 30 * 24 * 60 * 60 * 1000;

    sessions.set(session_token, {
      userId: row.userId,
      discord_access_token: row.discord_access_token,
      exp,
      device_name: device_name || "Windows",
    });

    return res.json({
      session_token,
      user: {
        id: me.id,
        username: me.username,
        global_name: me.global_name,
        avatar: me.avatar,
        email: me.email,
      },
      expires_at: exp,
    });
  } catch (e) {
    console.error("DEVICE CLAIM ERROR:", e);
    return res.status(500).json({ error: "server_error" });
  }
});

/* ============================================================
   Protected Discord proxy endpoints
   ============================================================ */
app.get("/api/me", async (req, res) => {
  try {
    const discordToken = resolveDiscordTokenFromAuthHeader(req.headers.authorization);
    if (!discordToken) return res.status(401).json({ error: "missing_token" });

    const r = await _fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${discordToken}` },
    });
    const text = await r.text();
    if (!r.ok) return res.status(r.status).json({ error: "discord_error", body: text });

    res.setHeader("Content-Type", "application/json");
    res.send(text);
  } catch (e) {
    console.error("ME ERROR:", e);
    res.status(500).json({ error: "server_error" });
  }
});

app.get("/api/discord/guilds", async (req, res) => {
  try {
    const discordToken = resolveDiscordTokenFromAuthHeader(req.headers.authorization);
    if (!discordToken) return res.status(401).json({ error: "missing_bearer_token" });

    const r = await _fetch("https://discord.com/api/users/@me/guilds", {
      headers: { Authorization: `Bearer ${discordToken}` },
    });
    const text = await r.text();
    if (!r.ok) return res.status(r.status).json({ error: "discord_error", body: text });

    res.setHeader("Content-Type", "application/json");
    res.send(text);
  } catch (e) {
    console.error("GUILDS ERROR:", e);
    res.status(500).json({ error: "server_error" });
  }
});

/* ============================================================
   Cleanup
   ============================================================ */
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of sessions.entries()) if (v.exp <= now) sessions.delete(k);
  for (const [k, v] of deviceCodes.entries()) if (v.exp <= now || v.used) deviceCodes.delete(k);
}, 60 * 60 * 1000);

/* ============================================================
   Start
   ============================================================ */
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Backend running on port ${port}`));
