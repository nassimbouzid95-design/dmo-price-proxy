// ============================================================
//  DMO Price Proxy
//  Petit serveur qui relaie les appels vers DMO Market.
//  Le navigateur d'un visiteur ne peut pas appeler DMO
//  directement (blocage CORS) ; il appelle CE serveur, qui
//  lui n'a pas cette restriction, et renvoie la réponse.
//
//  Aucune dépendance : Node 18+ fournit fetch en natif.
// ============================================================

const http = require("http");

const PORT = process.env.PORT || 3000;
const DMO = "https://dmo-market.onrender.com";

// Endpoints DMO qu'on autorise à relayer. On ne laisse pas
// proxifier n'importe quelle URL : seulement l'API du market.
const ALLOWED_PREFIXES = ["/api/"];

// Cache mémoire : on ne re-tape pas DMO à chaque visiteur.
// TTL court pour que les prix restent "live" sans marteler
// un service Render gratuit. Vidé au redémarrage, c'est voulu.
const cache = new Map();
const TTL_MS = 60 * 1000; // 60 s

function fromCache(key) {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.body;
  return null;
}
function toCache(key, body) {
  cache.set(key, { body, at: Date.now() });
  if (cache.size > 4000) cache.clear(); // garde-fou mémoire (512 Mo)
}

const server = http.createServer(async (req, res) => {
  // CORS : on autorise ton deck builder à nous appeler.
  // "*" convient pour un site public en lecture seule.
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }

  const url = new URL(req.url, `http://${req.headers.host}`);

  // Racine et /health : petit ping, utile pour UptimeRobot.
  if (url.pathname === "/" || url.pathname === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ ok: true, service: "dmo-price-proxy" }));
  }

  // On ne relaie que /api/*
  if (!ALLOWED_PREFIXES.some((p) => url.pathname.startsWith(p))) {
    res.writeHead(404, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "not_proxied", path: url.pathname }));
  }

  const target = DMO + url.pathname + url.search;

  const cached = fromCache(target);
  if (cached !== null) {
    res.writeHead(200, { "Content-Type": "application/json", "X-Cache": "HIT" });
    return res.end(cached);
  }

  try {
    const upstream = await fetch(target, {
      headers: { Accept: "application/json", "User-Agent": "dmo-deck-builder" },
    });
    const text = await upstream.text();

    // DMO gratuit peut mettre ~1 min à se réveiller : on
    // renvoie tel quel, le client réessaiera si besoin.
    if (upstream.ok) toCache(target, text);

    res.writeHead(upstream.status, {
      "Content-Type": "application/json",
      "X-Cache": "MISS",
    });
    res.end(text);
  } catch (err) {
    res.writeHead(502, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "upstream_unreachable", detail: String(err) }));
  }
});

server.listen(PORT, () => {
  console.log(`DMO price proxy en écoute sur le port ${PORT}`);
});
