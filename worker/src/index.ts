import { isValidEmail, normalizeEmail } from "../../docs/lib/email.js";
import { CONFLICT_ERROR, EMPTY_ERROR, conflictingIds, leavesVaultEmpty } from "../../docs/lib/merge.js";

// Do not log requests, bodies, tokens, passwords, or vault payloads.
const ALLOWED_ORIGIN = "https://tonychendds.github.io";
const SERVER_PBKDF2_ITERATIONS = 100_000;
const MAX_BODY_BYTES = 1_500_000;
const MAX_ITEMS = 40;
const MAX_CIPHERTEXT = 32_000;

interface Env {
  DB: D1Database;
}

interface D1Statement {
  bind(...values: Array<string | number | null>): D1Statement;
  first<T>(): Promise<T | null>;
  run(): Promise<unknown>;
  all<T>(): Promise<{ results?: T[] }>;
}

interface D1Database {
  prepare(query: string): D1Statement;
  batch(statements: D1Statement[]): Promise<unknown>;
}

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  password_salt: string;
}

interface ItemRow {
  item_id: string;
  ciphertext: string;
  iv: string;
  version: number;
  updated_at: number;
  deleted: number;
}

interface StoredItem {
  id: string;
  iv: string;
  ciphertext: string;
  version: number;
  updatedAt: number;
  deleted: boolean;
}

interface IncomingItem {
  id: string;
  iv: string;
  ciphertext: string;
  updatedAt: number;
  deleted: boolean;
  baseVersion: number;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const worker = {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (rejectedOrigin(request)) return cors(json({ error: "Origin is not allowed." }, 403));
    if (request.method === "OPTIONS") return cors(new Response(null, { status: 204 }));
    const url = new URL(request.url);
    try {
      if (request.method === "POST" && url.pathname === "/auth/register") return cors(await register(request, env));
      if (request.method === "POST" && url.pathname === "/auth/login") return cors(await login(request, env));
      if (request.method === "POST" && url.pathname === "/auth/logout") return cors(await logout(request, env));
      if (request.method === "GET" && url.pathname === "/auth/me") return cors(await me(request, env));
      if (request.method === "GET" && url.pathname === "/sync") return cors(await readVault(request, env));
      if (request.method === "PUT" && url.pathname === "/sync") return cors(await writeVault(request, env));
      return cors(json({ error: "Not found." }, 404));
    } catch {
      return cors(json({ error: "The sync server could not finish that request." }, 500));
    }
  },
};

export default worker;

function rejectedOrigin(request: Request): boolean {
  const origin = request.headers.get("Origin");
  return !!origin && origin !== ALLOWED_ORIGIN;
}

function cors(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  headers.set("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
  headers.set("Access-Control-Max-Age", "86400");
  headers.set("Vary", "Origin");
  return new Response(response.body, { status: response.status, headers });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

async function register(request: Request, env: Env): Promise<Response> {
  const credentials = await readCredentials(request);
  if (!credentials.ok) return json({ error: credentials.error }, 400);
  const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(credentials.email).first<{ id: string }>();
  if (existing) return json({ error: "An account with that email already exists." }, 409);
  const { hash, salt } = await hashAuth(credentials.authHash);
  const id = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO users (id, email, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(id, credentials.email, hash, salt, Date.now())
    .run();
  const token = await createSession(env, id);
  return json({ token, email: credentials.email }, 201);
}

async function login(request: Request, env: Env): Promise<Response> {
  const credentials = await readCredentials(request);
  if (!credentials.ok) return json({ error: credentials.error }, 400);
  const user = await env.DB.prepare("SELECT id, email, password_hash, password_salt FROM users WHERE email = ?")
    .bind(credentials.email)
    .first<UserRow>();
  if (!user) {
    await pbkdf2(credentials.authHash, crypto.getRandomValues(new Uint8Array(16)));
    return json({ error: "Email or master password does not match." }, 401);
  }
  if (!(await verifyAuth(credentials.authHash, user.password_salt, user.password_hash))) {
    return json({ error: "Email or master password does not match." }, 401);
  }
  const token = await createSession(env, user.id);
  return json({ token, email: user.email });
}

async function logout(request: Request, env: Env): Promise<Response> {
  const userId = await userIdFromRequest(request, env);
  if (!userId) return json({ error: "Sign in again." }, 401);
  const token = bearer(request);
  if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256Hex(token)).run();
  return json({ ok: true });
}

async function me(request: Request, env: Env): Promise<Response> {
  const user = await userFromRequest(request, env);
  if (!user) return json({ error: "Sign in again." }, 401);
  return json({ email: user.email });
}

async function readVault(request: Request, env: Env): Promise<Response> {
  const userId = await userIdFromRequest(request, env);
  if (!userId) return json({ error: "Sign in again." }, 401);
  const existing = await loadItems(env, userId);
  return json({ items: existing });
}

async function writeVault(request: Request, env: Env): Promise<Response> {
  const userId = await userIdFromRequest(request, env);
  if (!userId) return json({ error: "Sign in again." }, 401);
  const parsed = await readVaultBody(request);
  if (!parsed.ok) return json({ error: parsed.error }, 400);
  if (parsed.items.length === 0) return json({ ok: true, items: [] });

  const existing = await loadItems(env, userId);
  if (conflictingIds(existing, parsed.items).length > 0) {
    return json({ error: CONFLICT_ERROR, items: existing }, 409);
  }
  if (leavesVaultEmpty(existing, parsed.items) && !parsed.confirmEmpty) {
    return json({ error: EMPTY_ERROR }, 409);
  }

  const claimRow = await env.DB.prepare("SELECT COALESCE(MAX(generation), -1) AS generation FROM vault_claims WHERE user_id = ?")
    .bind(userId)
    .first<{ generation: number }>();
  const generation = (claimRow?.generation ?? -1) + 1;
  const statements: D1Statement[] = [
    env.DB.prepare("INSERT INTO vault_claims (user_id, generation) VALUES (?, ?)").bind(userId, generation),
  ];
  for (const item of parsed.items) {
    statements.push(
      env.DB.prepare(
        `INSERT INTO vault_items (user_id, item_id, ciphertext, iv, version, updated_at, deleted)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, item_id) DO UPDATE SET
           ciphertext = excluded.ciphertext,
           iv = excluded.iv,
           version = excluded.version,
           updated_at = excluded.updated_at,
           deleted = excluded.deleted`,
      ).bind(userId, item.id, item.ciphertext, item.iv, item.baseVersion + 1, item.updatedAt, item.deleted ? 1 : 0),
    );
  }
  try {
    await env.DB.batch(statements);
  } catch {
    return json({ error: CONFLICT_ERROR }, 409);
  }
  return json({
    ok: true,
    items: parsed.items.map((item) => ({
      id: item.id,
      version: item.baseVersion + 1,
      updatedAt: item.updatedAt,
    })),
  });
}

async function loadItems(env: Env, userId: string): Promise<StoredItem[]> {
  const listed = await env.DB.prepare(
    "SELECT item_id, ciphertext, iv, version, updated_at, deleted FROM vault_items WHERE user_id = ?",
  )
    .bind(userId)
    .all<ItemRow>();
  return (listed.results ?? []).map((row) => ({
    id: row.item_id,
    iv: row.iv,
    ciphertext: row.ciphertext,
    version: row.version,
    updatedAt: row.updated_at,
    deleted: row.deleted === 1,
  }));
}

async function createSession(env: Env, userId: string): Promise<string> {
  const token = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  await env.DB.prepare("INSERT INTO sessions (token_hash, user_id, created_at) VALUES (?, ?, ?)")
    .bind(await sha256Hex(token), userId, Date.now())
    .run();
  return token;
}

async function userIdFromRequest(request: Request, env: Env): Promise<string | null> {
  const token = bearer(request);
  if (!token) return null;
  const row = await env.DB.prepare("SELECT user_id FROM sessions WHERE token_hash = ?")
    .bind(await sha256Hex(token))
    .first<{ user_id: string }>();
  return row?.user_id ?? null;
}

async function userFromRequest(request: Request, env: Env): Promise<UserRow | null> {
  const userId = await userIdFromRequest(request, env);
  if (!userId) return null;
  return env.DB.prepare("SELECT id, email, password_hash, password_salt FROM users WHERE id = ?").bind(userId).first<UserRow>();
}

function bearer(request: Request): string | null {
  const header = request.headers.get("Authorization") ?? "";
  const match = /^Bearer\s+([A-Fa-f0-9]{64})$/.exec(header);
  return match ? match[1] : null;
}

async function readCredentials(
  request: Request,
): Promise<{ ok: true; email: string; authHash: string } | { ok: false; error: string }> {
  const body = await readObject(request);
  if (!body.ok) return body;
  const email = typeof body.value.email === "string" ? normalizeEmail(body.value.email) : "";
  const authHash = typeof body.value.authHash === "string" ? body.value.authHash.trim().toLowerCase() : "";
  if (!isValidEmail(email)) return { ok: false, error: "Enter a valid email address." };
  if (!/^[0-9a-f]{64}$/.test(authHash)) return { ok: false, error: "Sign-in material is invalid." };
  return { ok: true, email, authHash };
}

async function readVaultBody(
  request: Request,
): Promise<{ ok: true; items: IncomingItem[]; confirmEmpty: boolean } | { ok: false; error: string }> {
  const body = await readObject(request);
  if (!body.ok) return body;
  const confirmEmpty = body.value.confirmEmpty === true;
  const items = body.value.items;
  if (!Array.isArray(items)) return { ok: false, error: "The vault items are missing." };
  if (items.length > MAX_ITEMS) return { ok: false, error: "Too many entries in one sync." };
  const seen = new Set<string>();
  const parsed: IncomingItem[] = [];
  for (const raw of items) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { ok: false, error: "An entry is invalid." };
    const item = raw as Record<string, unknown>;
    const id = typeof item.id === "string" ? item.id.toLowerCase() : "";
    if (!UUID.test(id)) return { ok: false, error: "An entry id is invalid." };
    if (seen.has(id)) return { ok: false, error: "Duplicate entry in one sync." };
    seen.add(id);
    if (typeof item.iv !== "string" || !isBase64(item.iv, 64) || item.iv.length < 16) {
      return { ok: false, error: "An entry IV is invalid." };
    }
    if (typeof item.ciphertext !== "string" || !isBase64(item.ciphertext, MAX_CIPHERTEXT)) {
      return { ok: false, error: "An entry ciphertext is invalid." };
    }
    if (!isTimestamp(item.updatedAt)) return { ok: false, error: "An entry timestamp is invalid." };
    if (typeof item.deleted !== "boolean") return { ok: false, error: "An entry delete flag is invalid." };
    if (typeof item.baseVersion !== "number" || !Number.isSafeInteger(item.baseVersion) || item.baseVersion < 0) {
      return { ok: false, error: "An entry version is invalid." };
    }
    parsed.push({
      id,
      iv: item.iv,
      ciphertext: item.ciphertext,
      updatedAt: item.updatedAt,
      deleted: item.deleted,
      baseVersion: item.baseVersion,
    });
  }
  return { ok: true, items: parsed, confirmEmpty };
}

async function readObject(request: Request): Promise<{ ok: true; value: Record<string, unknown> } | { ok: false; error: string }> {
  const type = request.headers.get("Content-Type") ?? "";
  if (!type.toLowerCase().includes("application/json")) return { ok: false, error: "Expected JSON." };
  const length = Number(request.headers.get("Content-Length") ?? "0");
  if (Number.isFinite(length) && length > MAX_BODY_BYTES) return { ok: false, error: "That request is too large." };
  let text: string;
  try {
    text = await request.text();
  } catch {
    return { ok: false, error: "Expected JSON." };
  }
  if (text.length > MAX_BODY_BYTES) return { ok: false, error: "That request is too large." };
  try {
    const value = JSON.parse(text) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value)) return { ok: false, error: "Expected a JSON object." };
    return { ok: true, value: value as Record<string, unknown> };
  } catch {
    return { ok: false, error: "Expected JSON." };
  }
}

function isBase64(value: string, max: number): boolean {
  return value.length > 0 && value.length <= max && /^[A-Za-z0-9+/]+={0,2}$/.test(value);
}

function isTimestamp(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 && value < 4_000_000_000_000;
}

async function hashAuth(authHash: string): Promise<{ hash: string; salt: string }> {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(authHash, saltBytes);
  return { hash: bytesToHex(hash), salt: bytesToHex(saltBytes) };
}

async function verifyAuth(authHash: string, saltHex: string, hashHex: string): Promise<boolean> {
  const salt = hexToBytes(saltHex);
  if (!salt) return false;
  const actual = bytesToHex(await pbkdf2(authHash, salt));
  return constantEqual(actual, hashHex);
}

async function pbkdf2(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations: SERVER_PBKDF2_ITERATIONS },
    key,
    256,
  );
  return new Uint8Array(bits);
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToHex(new Uint8Array(digest));
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex: string): Uint8Array | null {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) return null;
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}

function constantEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let mismatch = 0;
  for (let index = 0; index < left.length; index += 1) mismatch |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return mismatch === 0;
}
