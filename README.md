# Vault

A personal zero-knowledge password manager. The master password and the vault encryption key stay on your device. The sync server stores an account, a session, and ciphertext.

The app is a static PWA: [https://tonychendds.github.io/vault/](https://tonychendds.github.io/vault/)

## What the server never sees

1. The email is normalized (Unicode NFKC, trimmed, lowercased).
2. The master password is stretched with PBKDF2-SHA256 for 600,000 iterations. The salt is SHA-256 of a fixed label plus that normalized email, so an account can be opened on a new device without a salt lookup.
3. HKDF-SHA256 splits the stretched key into `encKey` (AES-GCM 256) and `authKey`.
4. `encKey` is non-extractable and never leaves the device. It encrypts each entry with a new random IV on every save.
5. The device sends only SHA-256(`authKey`). The worker stores a second PBKDF2-SHA256 hash of that value with a random salt (100,000 iterations).
6. Sync uploads ciphertext, IV, a client `updatedAt`, a tombstone flag, and the last server version. Deletes are tombstones, so an older copy cannot resurrect an entry.

If you forget the master password, the vault cannot be recovered. There is no reset.

## App

Open the Pages site, or serve `docs/` with any static file server. On iPhone or iPad, use Share → Add to Home Screen. The layout is sized for iPhone and iPad mini Safari: 16px inputs, 44px controls, and safe-area padding.

The installable app is served from `docs/app/` at [https://tonychendds.github.io/vault/app/](https://tonychendds.github.io/vault/app/). `https://tonychendds.github.io/vault/` only redirects there. The worker URL lives only in `docs/app/config.js`:

```js
export const SYNC_URL = "https://vault-sync.tonychendds.workers.dev";
```

Until you deploy the worker, use **On device**. Entries stay encrypted in local storage on that browser. **Create account** does not unlock the vault unless the server responds with HTTP 201, a session token, and the same email.

A banner stays on screen when you are not signed in, when the server cannot be reached (local only), or when changes have not uploaded (unsynced).

The vault locks after 5 minutes without input, and 15 seconds after the tab is hidden. Copied secrets are cleared from the clipboard after 30 seconds when the browser allows a write without a new tap.

## Sync rules

- Merge is per entry, last-writer-wins on `updatedAt`.
- If the timestamps tie, a tombstone wins.
- Pushes send `baseVersion`. A mismatch returns 409; the app pulls again, merges, and retries.
- An empty local vault is never written over a non-empty server vault. A real delete of every entry sends tombstones and `confirmEmpty: true`. Omitting entries does not delete them.

## Deploy the worker

Do this from a machine logged into your Cloudflare account. Nothing here deploys it for you.

```bash
cd worker
npx wrangler d1 create vault-sync
```

Paste the database id into `worker/wrangler.toml` in place of `REPLACE_ME`.

```bash
npx wrangler d1 migrations apply vault-sync --remote
npx wrangler deploy
```

If the workers.dev hostname is not `vault-sync.tonychendds.workers.dev`, change `SYNC_URL` in `docs/app/config.js` and push. That file is the only frontend copy of the URL.

The worker allows browser calls only from `https://tonychendds.github.io`. It does not log request bodies. There is no account-recovery flow.

## GitHub Pages

The site is the `docs/` folder on `main`: [https://tonychendds.github.io/vault/](https://tonychendds.github.io/vault/). `docs/.nojekyll` is present so GitHub does not run Jekyll.

In the repository settings, open Pages, choose **Deploy from a branch**, select `main` and `/docs`, and save. The first publish can take a minute. A "Site not found" page means that setting is not on yet.

## Tests

```bash
node --test test/vault.test.mjs
```

The crypto test derives the real 600,000-iteration key and round-trips an entry. The other tests cover merge, tombstones, the empty-vault guard, and the 409 retry.
