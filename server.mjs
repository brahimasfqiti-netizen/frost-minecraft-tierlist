import { createServer } from "node:http";
import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { readFile, writeFile, rename, mkdir, unlink, chmod } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scrypt = promisify(scryptCallback);
const root = path.dirname(fileURLToPath(import.meta.url));
const publicRoot = path.join(root, "public");
const privateRoot = path.join(root, "private");
const databaseFile = path.join(privateRoot, "database.json");
const setupTokenFile = path.join(privateRoot, "setup-token.txt");
const host = process.env.HOST || "127.0.0.1";
const port = Number(process.env.PORT || 4173);
const isProduction = process.env.NODE_ENV === "production";

const modes = [
  { id: "sword", name: "Sword", icon: "⚔", accent: "#8da9ff" },
  { id: "axe", name: "Axe", icon: "⛏", accent: "#ff9d72" },
  { id: "crystal", name: "Crystal", icon: "◇", accent: "#c197ff" },
  { id: "uhc", name: "UHC", icon: "✦", accent: "#f6ca70" },
  { id: "pot", name: "Pot", icon: "◉", accent: "#f38bad" },
  { id: "nethpot", name: "NethPot", icon: "⬡", accent: "#ec8567" },
  { id: "smp", name: "SMP", icon: "⌂", accent: "#7ce0ad" },
  { id: "diapot", name: "DiaPot", icon: "◇", accent: "#66d7e8" },
  { id: "mace", name: "Mace", icon: "✧", accent: "#d1a5ff" },
  { id: "creeper", name: "Creeper", icon: "☠", accent: "#9edd68" }
];
const tiers = ["HTX", "HT1", "LT1", "HT2", "LT2", "HT3", "LT3", "HT4", "LT4", "HT5", "LT5"];
const tierPattern = /^(HTX|[HL]T[1-5])$/;

let database;
let writeQueue = Promise.resolve();
const sessions = new Map();
const loginAttempts = new Map();

function jsonResponse(response, status, value, extraHeaders = {}) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...extraHeaders
  });
  response.end(JSON.stringify(value));
}

function getCookie(request, name) {
  const cookies = request.headers.cookie || "";
  const entry = cookies.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
  return entry ? decodeURIComponent(entry.slice(name.length + 1)) : "";
}

function setSessionCookie(response, token, maxAge) {
  const secure = isProduction ? "; Secure" : "";
  response.setHeader("Set-Cookie", `frost_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${secure}`);
}

function getSession(request) {
  const token = getCookie(request, "frost_session");
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return { token, ...session };
}

function publicAccount(account) {
  return { username: account.username, role: account.role };
}

function requireRoles(request, response, allowedRoles) {
  const session = getSession(request);
  if (!session) {
    jsonResponse(response, 401, { error: "Inicia sesión para continuar." });
    return null;
  }
  if (!allowedRoles.includes(session.role)) {
    jsonResponse(response, 403, { error: "Tu rol no tiene permiso para esta acción." });
    return null;
  }
  return session;
}

function validUsername(value) {
  return typeof value === "string" && /^[a-zA-Z0-9_-]{3,20}$/.test(value);
}

function cleanText(value, maxLength) {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

async function hashPassword(password, salt = randomBytes(16).toString("hex")) {
  const hash = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return { salt, hash: Buffer.from(hash).toString("hex") };
}

async function verifyPassword(password, credentials) {
  try {
    const derived = await scrypt(password, credentials.salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
    const expected = Buffer.from(credentials.hash, "hex");
    const actual = Buffer.from(derived);
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

async function ensureDatabase() {
  await mkdir(privateRoot, { recursive: true });
  try {
    database = JSON.parse(await readFile(databaseFile, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    database = { accounts: [], ratings: [], requests: [], suggestions: [], changes: [] };
    await persistDatabase();
  }
  database.accounts ||= [];
  database.ratings ||= [];
  database.requests ||= [];
  database.suggestions ||= [];
  database.changes ||= [];
  if (database.accounts.length === 0) {
    try {
      await readFile(setupTokenFile, "utf8");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      const setupToken = randomBytes(24).toString("base64url");
      await writeFile(setupTokenFile, setupToken, { mode: 0o600 });
      try { await chmod(setupTokenFile, 0o600); } catch { /* Windows does not support POSIX file modes. */ }
      console.log(`\nFROST first-run owner setup token:\n${setupToken}\nUse it once at http://${host}:${port}/admin.html\n`);
    }
  }
}

function persistDatabase() {
  const snapshot = JSON.stringify(database, null, 2);
  writeQueue = writeQueue.then(async () => {
    const temporaryFile = `${databaseFile}.${randomBytes(6).toString("hex")}.tmp`;
    await writeFile(temporaryFile, snapshot, { mode: 0o600 });
    await rename(temporaryFile, databaseFile);
    try { await chmod(databaseFile, 0o600); } catch { /* Windows does not support POSIX file modes. */ }
  });
  return writeQueue;
}

function consumeRateLimit(request, key, maxAttempts, windowMs) {
  const ip = request.socket.remoteAddress || "unknown";
  const id = `${key}:${ip}`;
  const now = Date.now();
  const attempts = (loginAttempts.get(id) || []).filter((time) => now - time < windowMs);
  if (loginAttempts.size > 5000) {
    for (const [entryId, times] of loginAttempts) {
      if (!times.some((time) => now - time < windowMs)) loginAttempts.delete(entryId);
    }
  }
  if (attempts.length >= maxAttempts) {
    loginAttempts.set(id, attempts);
    return false;
  }
  attempts.push(now);
  loginAttempts.set(id, attempts);
  return true;
}

async function readJsonBody(request) {
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 16 * 1024) throw Object.assign(new Error("La solicitud es demasiado grande."), { status: 413 });
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw Object.assign(new Error("El cuerpo de la solicitud no es JSON válido."), { status: 400 });
  }
}

function checkSameOrigin(request, response) {
  const origin = request.headers.origin;
  if (!origin) return true;
  try {
    if (new URL(origin).host === request.headers.host) return true;
  } catch { /* Invalid origins are rejected below. */ }
  jsonResponse(response, 403, { error: "Origen de solicitud no permitido." });
  return false;
}

function tierCounts(ratings) {
  return Object.fromEntries(tiers.map((tier) => [tier, ratings.filter((rating) => rating.tier === tier).length]));
}

function publicRating(rating) {
  return {
    id: rating.id,
    playerName: rating.playerName,
    mode: rating.mode,
    tier: rating.tier,
    discord: rating.discord,
    server: rating.server,
    updatedAt: rating.updatedAt
  };
}

function recordRatingChange(action, rating, previousTier, username) {
  const entry = {
    id: randomBytes(12).toString("hex"),
    action,
    playerName: rating.playerName,
    mode: rating.mode,
    previousTier: previousTier || "",
    tier: action === "removed" ? "" : rating.tier,
    changedAt: new Date().toISOString(),
    changedBy: username
  };
  database.changes.unshift(entry);
  database.changes.length = Math.min(database.changes.length, 200);
  return entry;
}

async function handleApi(request, response, url) {
  const method = request.method;
  const route = url.pathname;
  if (method === "GET" && route === "/api/bootstrap") {
    const session = getSession(request);
    return jsonResponse(response, 200, {
      setupRequired: database.accounts.length === 0,
      session: session ? { username: session.username, role: session.role } : null,
      modes,
      tiers,
      tierCounts: tierCounts(database.ratings),
      ratings: database.ratings.map(publicRating),
      changes: database.changes.slice(0, 30)
    });
  }

  if (method === "POST" && !checkSameOrigin(request, response)) return;
  if (method === "POST") {
    const body = await readJsonBody(request);

    if (route === "/api/setup") {
      if (database.accounts.length > 0) return jsonResponse(response, 409, { error: "La configuración inicial ya se completó." });
      if (!consumeRateLimit(request, "setup", 5, 15 * 60 * 1000)) return jsonResponse(response, 429, { error: "Demasiados intentos. Espera 15 minutos." });
      const setupToken = (await readFile(setupTokenFile, "utf8")).trim();
      const suppliedToken = cleanText(body.setupToken, 200);
      const tokenMatches = suppliedToken.length === setupToken.length &&
        timingSafeEqual(Buffer.from(suppliedToken), Buffer.from(setupToken));
      if (!tokenMatches) return jsonResponse(response, 403, { error: "El código inicial no es válido." });
      if (!validUsername(body.username) || typeof body.password !== "string" || body.password.length < 12) {
        return jsonResponse(response, 400, { error: "Usa un nombre de 3–20 caracteres y una contraseña de al menos 12 caracteres." });
      }
      const credentials = await hashPassword(body.password);
      const account = { username: body.username, role: "owner", credentials, createdAt: new Date().toISOString() };
      database.accounts.push(account);
      await persistDatabase();
      await unlink(setupTokenFile);
      const token = randomBytes(32).toString("base64url");
      if (sessions.size > 5000) {
        for (const [sessionToken, session] of sessions) {
          if (session.expiresAt <= Date.now()) sessions.delete(sessionToken);
        }
      }
      sessions.set(token, { username: account.username, role: account.role, expiresAt: Date.now() + 8 * 60 * 60 * 1000 });
      setSessionCookie(response, token, 8 * 60 * 60);
      return jsonResponse(response, 201, { session: publicAccount(account) });
    }

    if (route === "/api/login") {
      if (!consumeRateLimit(request, "login", 10, 15 * 60 * 1000)) return jsonResponse(response, 429, { error: "Demasiados intentos. Prueba más tarde." });
      const account = database.accounts.find((entry) => entry.username.toLowerCase() === String(body.username || "").toLowerCase());
      const passwordValid = account && typeof body.password === "string" &&
        await verifyPassword(body.password, account.credentials);
      if (!passwordValid) return jsonResponse(response, 401, { error: "Usuario o contraseña incorrectos." });
      const token = randomBytes(32).toString("base64url");
      sessions.set(token, { username: account.username, role: account.role, expiresAt: Date.now() + 8 * 60 * 60 * 1000 });
      setSessionCookie(response, token, 8 * 60 * 60);
      return jsonResponse(response, 200, { session: publicAccount(account) });
    }

    if (route === "/api/logout") {
      const token = getCookie(request, "frost_session");
      sessions.delete(token);
      setSessionCookie(response, "", 0);
      return jsonResponse(response, 200, { ok: true });
    }

    if (route === "/api/requests") {
      if (!consumeRateLimit(request, "request", 4, 60 * 60 * 1000)) return jsonResponse(response, 429, { error: "Has enviado varias solicitudes. Inténtalo más tarde." });
      const playerName = cleanText(body.playerName, 16);
      const discord = cleanText(body.discord, 40);
      const mode = cleanText(body.mode, 20);
      const proof = cleanText(body.proof, 300);
      const region = cleanText(body.region, 40);
      const note = cleanText(body.note, 500);
      if (!/^[a-zA-Z0-9_]{3,16}$/.test(playerName)) return jsonResponse(response, 400, { error: "El nombre de Minecraft debe tener entre 3 y 16 letras, números o guiones bajos." });
      if (!discord || !modes.some((item) => item.id === mode)) return jsonResponse(response, 400, { error: "Indica tu Discord y selecciona un modo PvP válido." });
      if (proof) {
        try {
          const parsed = new URL(proof);
          if (!["http:", "https:"].includes(parsed.protocol)) throw new Error();
        } catch { return jsonResponse(response, 400, { error: "El enlace de evidencia debe ser una URL válida." }); }
      }
      const entry = {
        id: randomBytes(12).toString("hex"),
        playerName, discord, mode, proof, region, note,
        status: "pending",
        requestedAt: new Date().toISOString()
      };
      database.requests.unshift(entry);
      await persistDatabase();
      return jsonResponse(response, 201, { ok: true, message: "Solicitud recibida. El equipo de FROST la revisará." });
    }

    if (route === "/api/suggestions") {
      if (!consumeRateLimit(request, "suggestion", 5, 60 * 60 * 1000)) return jsonResponse(response, 429, { error: "Has enviado varias sugerencias. Inténtalo más tarde." });
      if (database.suggestions.filter((item) => item.status === "pending").length >= 1000) {
        return jsonResponse(response, 503, { error: "La cola de revisión está llena temporalmente. Vuelve a intentarlo más tarde." });
      }
      const action = cleanText(body.action, 12);
      const playerName = cleanText(body.playerName, 16);
      const mode = cleanText(body.mode, 20);
      const tier = cleanText(body.tier, 4);
      const discord = cleanText(body.discord, 40);
      const reason = cleanText(body.reason, 300);
      if (!["add", "update", "remove"].includes(action)) return jsonResponse(response, 400, { error: "Elige añadir, cambiar o quitar un jugador." });
      if (!/^[a-zA-Z0-9_]{3,16}$/.test(playerName) || !modes.some((item) => item.id === mode) || !reason) {
        return jsonResponse(response, 400, { error: "Comprueba el usuario de Minecraft, el modo y el motivo de la sugerencia." });
      }
      if (action !== "remove" && !tierPattern.test(tier)) return jsonResponse(response, 400, { error: "Selecciona un tier válido." });
      const existing = database.ratings.find((rating) => rating.playerName.toLowerCase() === playerName.toLowerCase() && rating.mode === mode);
      if (action === "add" && existing) return jsonResponse(response, 409, { error: "Ese jugador ya aparece en este modo. Envía una sugerencia de cambio en su lugar." });
      if (action !== "add" && !existing) return jsonResponse(response, 404, { error: "No encontramos a ese jugador en ese modo." });
      if (action === "update" && existing.tier === tier) return jsonResponse(response, 409, { error: "El jugador ya tiene ese tier en este modo." });
      database.suggestions.unshift({
        id: randomBytes(12).toString("hex"),
        action, playerName, mode, tier: action === "remove" ? "" : tier,
        currentTier: existing?.tier || "", discord, reason,
        status: "pending",
        submittedAt: new Date().toISOString()
      });
      await persistDatabase();
      return jsonResponse(response, 201, { ok: true, message: "Sugerencia enviada. Un tester la revisará antes de actualizar la lista." });
    }

    if (route === "/api/ratings") {
      const session = requireRoles(request, response, ["owner", "admin"]);
      if (!session) return;
      const playerName = cleanText(body.playerName, 16);
      const mode = cleanText(body.mode, 20);
      const tier = cleanText(body.tier, 4);
      if (!/^[a-zA-Z0-9_]{3,16}$/.test(playerName) || !modes.some((item) => item.id === mode) || !tierPattern.test(tier)) {
        return jsonResponse(response, 400, { error: "Comprueba el jugador, el modo y el tier seleccionados." });
      }
      const existing = database.ratings.find((rating) => rating.playerName.toLowerCase() === playerName.toLowerCase() && rating.mode === mode);
      const timestamp = new Date().toISOString();
      if (existing) {
        const previousTier = existing.tier;
        existing.tier = tier;
        existing.discord = cleanText(body.discord, 40);
        existing.server = cleanText(body.server, 40);
        existing.updatedAt = timestamp;
        existing.updatedBy = session.username;
        if (previousTier !== tier) recordRatingChange("updated", existing, previousTier, session.username);
      } else {
        const rating = {
          id: randomBytes(12).toString("hex"),
          playerName, mode, tier,
          discord: cleanText(body.discord, 40),
          server: cleanText(body.server, 40),
          updatedAt: timestamp,
          updatedBy: session.username
        };
        database.ratings.push(rating);
        recordRatingChange("added", rating, "", session.username);
      }
      await persistDatabase();
      return jsonResponse(response, 201, { ok: true });
    }

    const reviewMatch = route.match(/^\/api\/requests\/([a-f0-9]+)\/review$/);
    if (reviewMatch) {
      const session = requireRoles(request, response, ["owner", "admin", "tester"]);
      if (!session) return;
      const entry = database.requests.find((item) => item.id === reviewMatch[1]);
      if (!entry || entry.status !== "pending") return jsonResponse(response, 404, { error: "La solicitud no existe o ya fue revisada." });
      const action = cleanText(body.action, 12);
      if (action !== "approve" && action !== "reject") return jsonResponse(response, 400, { error: "Selecciona aprobar o rechazar." });
      if (action === "approve") {
        const tier = cleanText(body.tier, 4);
        if (!tierPattern.test(tier)) return jsonResponse(response, 400, { error: "Selecciona un tier válido antes de aprobar." });
        const existing = database.ratings.find((rating) => rating.playerName.toLowerCase() === entry.playerName.toLowerCase() && rating.mode === entry.mode);
        const rating = {
          id: existing?.id || randomBytes(12).toString("hex"),
          playerName: entry.playerName, mode: entry.mode, tier,
          discord: entry.discord, server: cleanText(body.server, 40),
          updatedAt: new Date().toISOString(), updatedBy: session.username
        };
        if (existing) {
          const previousTier = existing.tier;
          Object.assign(existing, rating);
          if (previousTier !== tier) recordRatingChange("updated", existing, previousTier, session.username);
        } else {
          database.ratings.push(rating);
          recordRatingChange("added", rating, "", session.username);
        }
      }
      entry.status = action === "approve" ? "approved" : "rejected";
      entry.reviewedAt = new Date().toISOString();
      entry.reviewedBy = session.username;
      entry.reviewNote = cleanText(body.reviewNote, 300);
      await persistDatabase();
      return jsonResponse(response, 200, { ok: true });
    }

    const suggestionReviewMatch = route.match(/^\/api\/suggestions\/([a-f0-9]+)\/review$/);
    if (suggestionReviewMatch) {
      const session = requireRoles(request, response, ["owner", "admin", "tester"]);
      if (!session) return;
      const suggestion = database.suggestions.find((item) => item.id === suggestionReviewMatch[1]);
      if (!suggestion || suggestion.status !== "pending") return jsonResponse(response, 404, { error: "La sugerencia no existe o ya fue revisada." });
      const action = cleanText(body.action, 12);
      if (!["approve", "reject"].includes(action)) return jsonResponse(response, 400, { error: "Selecciona aprobar o rechazar." });
      if (action === "approve") {
        const index = database.ratings.findIndex((rating) => rating.playerName.toLowerCase() === suggestion.playerName.toLowerCase() && rating.mode === suggestion.mode);
        const existing = index < 0 ? null : database.ratings[index];
        if (suggestion.action === "add") {
          if (existing) return jsonResponse(response, 409, { error: "El jugador ya fue añadido. Actualiza la lista y revisa la sugerencia." });
          const rating = {
            id: randomBytes(12).toString("hex"),
            playerName: suggestion.playerName, mode: suggestion.mode, tier: suggestion.tier,
            discord: suggestion.discord, server: "FROST ranked",
            updatedAt: new Date().toISOString(), updatedBy: session.username
          };
          database.ratings.push(rating);
          recordRatingChange("added", rating, "", session.username);
        } else {
          if (!existing || existing.tier !== suggestion.currentTier) return jsonResponse(response, 409, { error: "La clasificación cambió desde que se envió esta sugerencia. Actualiza la lista antes de revisarla." });
          if (suggestion.action === "update") {
            const previousTier = existing.tier;
            existing.tier = suggestion.tier;
            existing.updatedAt = new Date().toISOString();
            existing.updatedBy = session.username;
            recordRatingChange("updated", existing, previousTier, session.username);
          } else {
            database.ratings.splice(index, 1);
            recordRatingChange("removed", existing, existing.tier, session.username);
          }
        }
      }
      suggestion.status = action === "approve" ? "approved" : "rejected";
      suggestion.reviewedAt = new Date().toISOString();
      suggestion.reviewedBy = session.username;
      await persistDatabase();
      return jsonResponse(response, 200, { ok: true });
    }

    if (route === "/api/accounts") {
      if (!requireRoles(request, response, ["owner"])) return;
      if (!validUsername(body.username) || typeof body.password !== "string" || body.password.length < 12) {
        return jsonResponse(response, 400, { error: "Usa un nombre de 3–20 caracteres y una contraseña de al menos 12 caracteres." });
      }
      if (!["owner", "admin", "tester"].includes(body.role)) return jsonResponse(response, 400, { error: "Rol no válido." });
      if (database.accounts.some((account) => account.username.toLowerCase() === body.username.toLowerCase())) {
        return jsonResponse(response, 409, { error: "Ese nombre de usuario ya existe." });
      }
      const credentials = await hashPassword(body.password);
      database.accounts.push({ username: body.username, role: body.role, credentials, createdAt: new Date().toISOString() });
      await persistDatabase();
      return jsonResponse(response, 201, { ok: true });
    }
  }

  if (method === "GET" && route === "/api/accounts") {
    if (!requireRoles(request, response, ["owner"])) return;
    return jsonResponse(response, 200, {
      accounts: database.accounts.map((account) => ({ username: account.username, role: account.role, createdAt: account.createdAt }))
    });
  }

  if (method === "GET" && route === "/api/requests") {
    if (!requireRoles(request, response, ["owner", "admin", "tester"])) return;
    return jsonResponse(response, 200, { requests: database.requests });
  }

  if (method === "GET" && route === "/api/suggestions") {
    if (!requireRoles(request, response, ["owner", "admin", "tester"])) return;
    return jsonResponse(response, 200, { suggestions: database.suggestions });
  }

  if (method === "DELETE" && route.startsWith("/api/ratings/")) {
    if (!checkSameOrigin(request, response)) return;
    if (!requireRoles(request, response, ["owner", "admin"])) return;
    const id = route.slice("/api/ratings/".length);
    const index = database.ratings.findIndex((rating) => rating.id === id);
    if (index < 0) return jsonResponse(response, 404, { error: "No se encontró la clasificación." });
    const [rating] = database.ratings.splice(index, 1);
    recordRatingChange("removed", rating, rating.tier, getSession(request).username);
    await persistDatabase();
    return jsonResponse(response, 200, { ok: true });
  }

  return jsonResponse(response, 404, { error: "Ruta no encontrada." });
}

function contentType(file) {
  const extension = path.extname(file).toLowerCase();
  return ({
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".webmanifest": "application/manifest+json"
  })[extension] || "application/octet-stream";
}

async function serveStatic(request, response, url) {
  let requestPath = decodeURIComponent(url.pathname);
  if (requestPath === "/") requestPath = "/index.html";
  if (requestPath === "/admin" || requestPath === "/admin/") requestPath = "/admin.html";
  const resolvedPath = path.resolve(publicRoot, `.${requestPath}`);
  if (!resolvedPath.startsWith(`${publicRoot}${path.sep}`) && resolvedPath !== publicRoot) {
    return jsonResponse(response, 403, { error: "Ruta no permitida." });
  }
  try {
    const content = await readFile(resolvedPath);
    response.writeHead(200, {
      "Content-Type": contentType(resolvedPath),
      "Cache-Control": resolvedPath.endsWith(".html") ? "no-store" : "public, max-age=3600",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    });
    response.end(content);
  } catch (error) {
    if (error.code === "ENOENT" || error.code === "EISDIR") return jsonResponse(response, 404, { error: "Página no encontrada." });
    throw error;
  }
}

await ensureDatabase();
const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    if (url.pathname.startsWith("/api/")) return await handleApi(request, response, url);
    if (request.method !== "GET" && request.method !== "HEAD") return jsonResponse(response, 405, { error: "Método no permitido." });
    return await serveStatic(request, response, url);
  } catch (error) {
    console.error("Request failed:", error);
    if (!response.headersSent) jsonResponse(response, error.status || 500, { error: error.status ? error.message : "Error interno del servidor." });
    else response.destroy();
  }
});

server.listen(port, host, () => {
  console.log(`FROST Tierlist ready at http://${host}:${port}`);
});

function shutdown() {
  server.close(() => process.exit(0));
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
