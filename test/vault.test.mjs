import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { PBKDF2_ITERATIONS, decryptJson, deriveKeys, encryptJson } from "../docs/app/lib/crypto.js";
import { normalizeEmail } from "../docs/app/lib/email.js";
import {
  CONFLICT_ERROR,
  EMPTY_ERROR,
  applyIncoming,
  conflictingIds,
  leavesVaultEmpty,
  mergeEntries,
  planSync,
  uploadPlan,
} from "../docs/app/lib/merge.js";
import { generatePassword } from "../docs/app/lib/password.js";
import { buildBackup, parseBackup } from "../docs/app/lib/backup.js";

const root = new URL("../", import.meta.url);

test("email normalization", () => {
  assert.equal(normalizeEmail("  Ada@Example.COM "), "ada@example.com");
  assert.equal(normalizeEmail("Ａ@Example.com"), "a@example.com");
});

test("password generator length and charsets", () => {
  const password = generatePassword(20, { lower: true, upper: true, digit: true, symbol: false });
  assert.equal(password.length, 20);
  assert.match(password, /[a-z]/);
  assert.match(password, /[A-Z]/);
  assert.match(password, /[0-9]/);
  assert.doesNotMatch(password, /[^a-zA-Z0-9]/);
  const symbols = generatePassword(12, { lower: false, upper: false, digit: false, symbol: true });
  const symbolAlphabet = "!@#$%^&*()-_=+[]{}?";
  assert.equal(symbols.length, 12);
  for (const character of symbols) assert.equal(symbolAlphabet.includes(character), true);
  assert.notEqual(password, generatePassword(20, { lower: true, upper: true, digit: true, symbol: true }));
  assert.throws(() => generatePassword(10, { lower: false, upper: false, digit: false, symbol: false }));
});

test("merge, tombstones, empty vault guard, and optimistic retry", () => {
  const newerDelete = mergeEntries(
    [{ id: "a", updatedAt: 20, deleted: true, version: 1, dirty: true, iv: "1", ciphertext: "x" }],
    [{ id: "a", updatedAt: 10, deleted: false, version: 4, iv: "2", ciphertext: "y" }],
  );
  assert.equal(newerDelete[0].deleted, true);
  assert.equal(newerDelete[0].ciphertext, "x");
  assert.equal(newerDelete[0].version, 4);
  assert.equal(newerDelete[0].dirty, true);

  const newerLive = mergeEntries(
    [{ id: "a", updatedAt: 10, deleted: true, version: 1, dirty: true, iv: "1", ciphertext: "x" }],
    [{ id: "a", updatedAt: 20, deleted: false, version: 3, iv: "2", ciphertext: "y" }],
  );
  assert.equal(newerLive[0].deleted, false);
  assert.equal(newerLive[0].dirty, false);
  assert.equal(newerLive[0].ciphertext, "y");

  const tie = mergeEntries(
    [{ id: "a", updatedAt: 10, deleted: false, version: 1, dirty: true, iv: "1", ciphertext: "x" }],
    [{ id: "a", updatedAt: 10, deleted: true, version: 2, iv: "2", ciphertext: "y" }],
  );
  assert.equal(tie[0].deleted, true);
  assert.equal(tie[0].dirty, false);

  const server = [{ id: "a", version: 1, updatedAt: 10, deleted: false, iv: "aa", ciphertext: "bb" }];
  assert.equal(uploadPlan([], server).allow, false);
  assert.equal(uploadPlan([{ id: "a", deleted: true, updatedAt: 4, version: 1, dirty: true }], server).allow, false);
  const intentional = uploadPlan([{ id: "a", deleted: true, updatedAt: 12, version: 1, dirty: true }], server);
  assert.equal(intentional.allow, true);
  assert.equal(intentional.confirmEmpty, true);

  const adopted = planSync([], server);
  assert.equal(adopted.merged.length, 1);
  assert.equal(adopted.merged[0].ciphertext, "bb");
  assert.equal(adopted.plan.allow, true);
  assert.equal(adopted.plan.items.length, 0);

  assert.deepEqual(conflictingIds(server, [{ id: "a", baseVersion: 1 }]), []);
  assert.deepEqual(conflictingIds(server, [{ id: "a", baseVersion: 0 }]), ["a"]);
  assert.equal(leavesVaultEmpty(server, [{ id: "a", deleted: true }]), true);
  assert.equal(leavesVaultEmpty(server, []), false);

  const wrote = applyIncoming(server, [{ id: "a", baseVersion: 1, updatedAt: 20, deleted: false, iv: "cc", ciphertext: "dd" }]);
  assert.equal(wrote.status, 200);
  assert.equal(wrote.items[0].version, 2);
  const conflict = applyIncoming(wrote.items, [{ id: "a", baseVersion: 1, updatedAt: 30, deleted: false, iv: "ee", ciphertext: "ff" }]);
  assert.equal(conflict.status, 409);
  assert.equal(conflict.error, CONFLICT_ERROR);
  const resolved = planSync(
    [{ id: "a", version: 1, updatedAt: 30, deleted: false, dirty: true, iv: "ee", ciphertext: "ff" }],
    conflict.items,
  );
  assert.equal(resolved.merged[0].updatedAt, 30);
  assert.equal(resolved.merged[0].version, 2);
  const retry = applyIncoming(
    conflict.items,
    resolved.plan.items.map((item) => ({
      id: item.id,
      baseVersion: item.version,
      updatedAt: item.updatedAt,
      deleted: item.deleted,
      iv: item.iv,
      ciphertext: item.ciphertext,
    })),
  );
  assert.equal(retry.status, 200);
  assert.equal(retry.items[0].version, 3);
  assert.equal(retry.items[0].ciphertext, "ff");

  const wiped = applyIncoming(server, [{ id: "a", baseVersion: 1, updatedAt: 12, deleted: true, iv: "aa", ciphertext: "zz" }], false);
  assert.equal(wiped.status, 409);
  assert.equal(wiped.error, EMPTY_ERROR);
  const confirmed = applyIncoming(server, [{ id: "a", baseVersion: 1, updatedAt: 12, deleted: true, iv: "aa", ciphertext: "zz" }], true);
  assert.equal(confirmed.status, 200);
  assert.equal(confirmed.items[0].deleted, true);
});

test("backup file keeps ciphertext only", () => {
  const backup = buildBackup(
    "a@b.co",
    [{ id: "1", iv: "aa", ciphertext: "bb", updatedAt: 5, deleted: false, version: 1, password: "super-secret", title: "Bank" }],
    PBKDF2_ITERATIONS,
  );
  const json = JSON.stringify(backup);
  assert.equal(json.includes("super-secret"), false);
  assert.equal(json.includes("Bank"), false);
  const parsed = parseBackup(backup);
  assert.equal(parsed.items[0].ciphertext, "bb");
  assert.equal(parsed.iterations, PBKDF2_ITERATIONS);
  assert.throws(() => parseBackup({ ...backup, items: [{ ...backup.items[0], password: "x" }] }));
});

test("repo wiring stays free of secrets and recovery", () => {
  const worker = readFileSync(new URL("worker/src/index.ts", root), "utf8");
  const toml = readFileSync(new URL("worker/wrangler.toml", root), "utf8");
  const config = readFileSync(new URL("docs/app/config.js", root), "utf8");
  const app = readFileSync(new URL("docs/app/app.js", root), "utf8");
  const html = readFileSync(new URL("docs/app/index.html", root), "utf8");
  const rootHtml = readFileSync(new URL("docs/index.html", root), "utf8");
  const css = readFileSync(new URL("docs/app/styles.css", root), "utf8");
  const sql = readFileSync(new URL("worker/migrations/0001_init.sql", root), "utf8");
  assert.equal(/recovery_email|reset-request|password_resets|RESET_RELAY/i.test(worker), false);
  assert.equal(worker.includes("console."), false);
  assert.match(worker, /ALLOWED_ORIGIN = "https:\/\/tonychendds\.github\.io"/);
  assert.match(toml, /name = "vault-sync"/);
  assert.match(toml, /binding = "DB"/);
  assert.match(toml, /database_id = "[0-9a-f-]{36}"/);
  const sw = readFileSync(new URL("docs/app/sw.js", root), "utf8");
  const oldSw = readFileSync(new URL("docs/sw.js", root), "utf8");
  assert.match(sw, /vault-app-v1/);
  assert.match(oldSw, /registration\.unregister/);
  assert.match(oldSw, /caches\.delete/);
  assert.equal(rootHtml.includes("manifest"), false);
  assert.match(rootHtml, /url=\.\/app\//);
  assert.match(rootHtml, /location\.replace\("\.\/app\/"\)/);
  assert.match(worker, /No account exists for that email/);
  assert.match(app, /Use Create to make one/);
  assert.match(html, /aria-label="Show password"/);
  assert.equal(html.includes("manifest.json"), false);
  assert.match(html, /href="\/vault\/app\/vault-app\.webmanifest"/);
  assert.match(html, /id="install-button"/);
  assert.match(html, /Install app/);
  assert.match(app, /beforeinstallprompt/);
  assert.match(app, /register\("\/vault\/app\/sw\.js", \{ scope: "\/vault\/app\/" \}\)/);
  const manifest = JSON.parse(readFileSync(new URL("docs/app/vault-app.webmanifest", root), "utf8"));
  assert.equal(manifest.id, "/vault/app/");
  assert.equal(manifest.start_url, "/vault/app/");
  assert.equal(manifest.scope, "/vault/app/");
  assert.equal(manifest.display, "standalone");
  assert.equal(manifest.icons.some((icon) => icon.sizes === "192x192" && icon.type === "image/png" && icon.src === "/vault/app/icon-192.png"), true);
  assert.equal(manifest.icons.some((icon) => icon.sizes === "512x512" && icon.type === "image/png" && icon.purpose === "any"), true);
  assert.equal(manifest.icons.some((icon) => icon.purpose === "maskable" && icon.type === "image/png" && icon.src === "/vault/app/icon-maskable-512.png"), true);
  assert.match(sw, /SHELL_PATHS/);
  assert.equal(sw.includes("manifest.json"), false);
  assert.equal(sw.includes('"manifest.webmanifest"'), false);
  assert.match(sw, /vault-app\.webmanifest/);
  assert.match(sw, /\/vault\/app\//);
  assert.match(sw, /caches\.delete/);
  assert.match(sw, /clients\.claim/);
  assert.match(config, /https:\/\/vault-sync\.tonychendds\.workers\.dev/);
  assert.equal(app.includes("workers.dev"), false);
  assert.equal(html.includes("workers.dev"), false);
  assert.match(html, /cannot be recovered/);
  assert.match(css, /pointer-events:\s*none/);
  assert.equal(sql.includes("recovery_email"), false);
  assert.equal(PBKDF2_ITERATIONS >= 600_000, true);
});

test("crypto round trip", { timeout: 180_000 }, async () => {
  const email = "ada@example.com";
  const password = "correct horse battery";
  const first = await deriveKeys(email, password);
  const second = await deriveKeys(`  Ada@Example.com `, password);
  assert.equal(first.authHash, second.authHash);
  assert.match(first.authHash, /^[0-9a-f]{64}$/);
  assert.notEqual(first.authHash, password);
  await assert.rejects(crypto.subtle.exportKey("raw", first.encKey));

  const payload = { title: "Bank", username: "ada", password: "s3cret-value", url: "https://bank.example", notes: "door code" };
  const packed = await encryptJson(first.encKey, payload);
  const again = await encryptJson(first.encKey, payload);
  assert.notEqual(packed.iv, again.iv);
  const decoded = Buffer.from(packed.ciphertext, "base64").toString("utf8");
  assert.equal(decoded.includes("s3cret-value"), false);
  assert.deepEqual(await decryptJson(second.encKey, packed.iv, packed.ciphertext), payload);

  const wrong = await deriveKeys(email, "wrong password");
  await assert.rejects(decryptJson(wrong.encKey, packed.iv, packed.ciphertext));
  const otherEmail = await deriveKeys("other@example.com", password);
  assert.notEqual(otherEmail.authHash, first.authHash);
  await assert.rejects(decryptJson(otherEmail.encKey, packed.iv, packed.ciphertext));
});
