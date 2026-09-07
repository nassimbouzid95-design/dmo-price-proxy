// ============================================================
//  DMO Proxy v2
//  1) Relais des prix DMO (comme avant, contourne le CORS).
//  2) OAuth Discord en direct, avec scope "identify" SEULEMENT
//     (donc pas d'accès à l'email), puis création d'une session
//     Supabase valide — la sécurité des policies SQL est préservée.
//
//  SECRETS : fournis en variables d'environnement Render, jamais
//  dans le code.
//    DISCORD_CLIENT_ID
//    DISCORD_CLIENT_SECRET
//    SUPABASE_URL            (ex: https://xxxx.supabase.co)
//    SUPABASE_SERVICE_ROLE   (la clé service_role, secrète)
//    SITE_URL                (ex: https://dmo-deck-builder.onrender.com)
//    PROXY_URL               (l'URL publique de CE proxy)
// ============================================================

const http = require("http");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const DMO = "https://dmo-market.onrender.com";

const DISCORD_ID     = process.env.DISCORD_CLIENT_ID || "";
const DISCORD_SECRET = process.env.DISCORD_CLIENT_SECRET || "";
const SUPABASE_URL   = (process.env.SUPABASE_URL || "").replace(/\/+$/, "");
const SERVICE_ROLE   = process.env.SUPABASE_SERVICE_ROLE || "";
const SITE_URL       = (process.env.SITE_URL || "").replace(/\/+$/, "");
const SELF_URL       = (process.env.PROXY_URL || "").replace(/\/+$/, "");

const REDIRECT_URI = SELF_URL + "/auth/discord/callback";

// ---- cache prix (inchangé) ----
const cache = new Map();
const TTL_MS = 60 * 1000;
const fromCache = (k) => { const h = cache.get(k); return h && Date.now() - h.at < TTL_MS ? h.body : null; };
const toCache = (k, b) => { cache.set(k, { body: b, at: Date.now() }); if (cache.size > 4000) cache.clear(); };

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function redirect(res, url) { res.writeHead(302, { Location: url }); res.end(); }

const server = http.createServer(async (req, res) => {
  cors(res);
  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname;

  // --- ping ---
  if (path === "/" || path === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ ok: true, service: "dmo-proxy-v2" }));
  }

  // ========== 1) LOGIN DISCORD : redirige vers Discord, scope identify seul ==========
  if (path === "/auth/discord/login") {
    const state = crypto.randomBytes(16).toString("hex");
    const auth = "https://discord.com/api/oauth2/authorize?"
      + "client_id=" + encodeURIComponent(DISCORD_ID)
      + "&redirect_uri=" + encodeURIComponent(REDIRECT_URI)
      + "&response_type=code"
      + "&scope=identify"           // ← PAS d'email
      + "&state=" + state;
    return redirect(res, auth);
  }

  // ========== 2) CALLBACK : échange le code, crée la session Supabase ==========
  if (path === "/auth/discord/callback") {
    const code = url.searchParams.get("code");
    if (!code) { res.writeHead(400); return res.end("no code"); }
    try {
      // a) code -> token Discord
      const tokRes = await fetch("https://discord.com/api/oauth2/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: DISCORD_ID,
          client_secret: DISCORD_SECRET,
          grant_type: "authorization_code",
          code,
          redirect_uri: REDIRECT_URI,
        }),
      });
      const tok = await tokRes.json();
      if (!tok.access_token) throw new Error("discord token failed");

      // b) token -> profil Discord (pseudo, avatar, id) — pas d'email
      const meRes = await fetch("https://discord.com/api/users/@me", {
        headers: { Authorization: "Bearer " + tok.access_token },
      });
      const me = await meRes.json();
      const discordId = me.id;
      const name = me.global_name || me.username || "Duelliste";
      const avatar = me.avatar
        ? `https://cdn.discordapp.com/avatars/${me.id}/${me.avatar}.png`
        : "";

      // c) email synthétique stable (jamais montré) : l'API Supabase exige
      //    un identifiant ; on en fabrique un à partir de l'id Discord.
      const fakeEmail = "discord_" + discordId + "@dmo.local";

      // d) crée l'utilisateur Supabase s'il n'existe pas (admin API)
      const meta = { name, avatar_url: avatar, provider: "discord", discord_id: discordId };
      const createRes = await fetch(SUPABASE_URL + "/auth/v1/admin/users", {
        method: "POST",
        headers: {
          apikey: SERVICE_ROLE,
          Authorization: "Bearer " + SERVICE_ROLE,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: fakeEmail,
          email_confirm: true,
          user_metadata: meta,
        }),
      });
      const createBody = await createRes.text();
      console.log("[AUTH] admin/users status:", createRes.status, "body:", createBody.slice(0, 300));

      // e) génère un lien de session (magic link) pour obtenir des jetons
      const linkRes = await fetch(SUPABASE_URL + "/auth/v1/admin/generate_link", {
        method: "POST",
        headers: {
          apikey: SERVICE_ROLE,
          Authorization: "Bearer " + SERVICE_ROLE,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ type: "magiclink", email: fakeEmail }),
      });
      const linkBody = await linkRes.text();
      console.log("[AUTH] generate_link status:", linkRes.status, "body:", linkBody.slice(0, 400));
      let link = {};
      try { link = JSON.parse(linkBody); } catch (e) {}
      const hashedToken = link.hashed_token || (link.properties && link.properties.hashed_token);
      console.log("[AUTH] hashed_token présent:", !!hashedToken);

      // f) échange le hashed_token contre une vraie session (access + refresh)
      const verifyRes = await fetch(SUPABASE_URL + "/auth/v1/verify", {
        method: "POST",
        headers: { apikey: SERVICE_ROLE, "Content-Type": "application/json" },
        body: JSON.stringify({ type: "magiclink", token: hashedToken }),
      });
      const verifyBody = await verifyRes.text();
      console.log("[AUTH] verify status:", verifyRes.status, "body:", verifyBody.slice(0, 400));
      let session = {};
      try { session = JSON.parse(verifyBody); } catch (e) {}
      if (!session.access_token) throw new Error("supabase session failed — verify:" + verifyRes.status + " link:" + linkRes.status);

      // g) renvoie l'utilisateur au site avec les jetons dans le hash
      const back = SITE_URL + "/#access_token=" + session.access_token
        + "&refresh_token=" + (session.refresh_token || "");
      return redirect(res, back);
    } catch (err) {
      res.writeHead(500, { "Content-Type": "text/plain" });
      return res.end("auth error: " + String(err));
    }
  }

  // ========== 3) RELAIS PRIX (inchangé) ==========
  if (path.startsWith("/api/")) {
    const target = DMO + path + url.search;
    const hit = fromCache(target);
    if (hit !== null) {
      res.writeHead(200, { "Content-Type": "application/json", "X-Cache": "HIT" });
      return res.end(hit);
    }
    try {
      const up = await fetch(target, { headers: { Accept: "application/json", "User-Agent": "dmo-proxy" } });
      const text = await up.text();
      if (up.ok) toCache(target, text);
      res.writeHead(up.status, { "Content-Type": "application/json", "X-Cache": "MISS" });
      return res.end(text);
    } catch (err) {
      res.writeHead(502, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "upstream_unreachable" }));
    }
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "not_found", path }));
});

server.listen(PORT, () => console.log("DMO proxy v2 on " + PORT));
