import { normalizeEmail } from "./email.js";

/** Client KDF cost. The master password never leaves the device. */
export const PBKDF2_ITERATIONS = 600_000;

const KDF_SALT_PREFIX = "vault-kdf-salt-v1:";
const HKDF_SALT_LABEL = "vault-hkdf-salt-v1";

function encode(value) {
  return new TextEncoder().encode(value);
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

export function bytesToHex(bytes) {
  let hex = "";
  for (let index = 0; index < bytes.length; index += 1) {
    hex += bytes[index].toString(16).padStart(2, "0");
  }
  return hex;
}

export function bytesToBase64(bytes) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) binary += String.fromCharCode(bytes[index]);
  return btoa(binary);
}

export function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

/**
 * PBKDF2-SHA256(master password, salt from the normalized email), then HKDF
 * splits the result into an AES-GCM encKey and an authKey. Only SHA-256(authKey)
 * is returned for the server. encKey is not extractable.
 */
export async function deriveKeys(email, password) {
  const salt = await sha256(encode(`${KDF_SALT_PREFIX}${normalizeEmail(email)}`));
  const passwordKey = await crypto.subtle.importKey("raw", encode(password), "PBKDF2", false, ["deriveBits"]);
  const masterBits = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
      passwordKey,
      256,
    ),
  );
  const hkdfSalt = await sha256(encode(HKDF_SALT_LABEL));
  const hkdfKey = await crypto.subtle.importKey("raw", masterBits, "HKDF", false, ["deriveBits"]);
  const encBits = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: hkdfSalt, info: encode("vault-enc-v1") },
      hkdfKey,
      256,
    ),
  );
  const authBits = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: hkdfSalt, info: encode("vault-auth-v1") },
      hkdfKey,
      256,
    ),
  );
  const encKey = await crypto.subtle.importKey("raw", encBits, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  const authDigest = new Uint8Array(await crypto.subtle.digest("SHA-256", authBits));
  const authHash = bytesToHex(authDigest);
  masterBits.fill(0);
  encBits.fill(0);
  authBits.fill(0);
  authDigest.fill(0);
  return { encKey, authHash };
}

/** AES-GCM with a fresh 96-bit IV. The auth tag is part of the ciphertext. */
export async function encryptJson(key, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encode(JSON.stringify(value));
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
  plaintext.fill(0);
  return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(cipher) };
}

export async function decryptJson(key, ivBase64, ciphertextBase64) {
  const iv = base64ToBytes(ivBase64);
  const ciphertext = base64ToBytes(ciphertextBase64);
  const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext));
  const text = new TextDecoder().decode(plain);
  plain.fill(0);
  return JSON.parse(text);
}
