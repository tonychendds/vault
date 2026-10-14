/** Normalize an account email the same way on the device and the worker. */
export function normalizeEmail(email) {
  return String(email).normalize("NFKC").trim().toLowerCase();
}

export function isValidEmail(email) {
  return typeof email === "string" && email.length <= 200 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
