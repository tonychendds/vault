export const BACKUP_FORMAT = "vault-backup-v1";

/** Ciphertext-only backup. Plaintext fields on the input are not copied. */
export function buildBackup(email, items, iterations) {
  return {
    format: BACKUP_FORMAT,
    exportedAt: Date.now(),
    email,
    kdf: {
      name: "PBKDF2-SHA256",
      iterations,
      salt: "normalized-email",
    },
    items: items.map((item) => ({
      id: item.id,
      iv: item.iv,
      ciphertext: item.ciphertext,
      updatedAt: item.updatedAt,
      deleted: !!item.deleted,
      version: item.version || 0,
    })),
  };
}

export function parseBackup(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Backup file is not valid.");
  if (value.format !== BACKUP_FORMAT) throw new Error("Unrecognized backup file.");
  if (typeof value.email !== "string" || !value.email) throw new Error("Backup is missing an email.");
  if (
    !value.kdf ||
    value.kdf.name !== "PBKDF2-SHA256" ||
    value.kdf.salt !== "normalized-email" ||
    typeof value.kdf.iterations !== "number"
  ) {
    throw new Error("Backup uses an unknown key derivation.");
  }
  if (!Array.isArray(value.items)) throw new Error("Backup is missing entries.");
  const items = value.items.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("Backup entry is invalid.");
    if (typeof item.id !== "string" || typeof item.iv !== "string" || typeof item.ciphertext !== "string") {
      throw new Error("Backup entry is invalid.");
    }
    if (typeof item.updatedAt !== "number" || !Number.isSafeInteger(item.updatedAt) || item.updatedAt <= 0) {
      throw new Error("Backup entry is invalid.");
    }
    if (item.password != null || item.title != null || item.notes != null || item.username != null) {
      throw new Error("Backup must contain ciphertext only.");
    }
    return {
      id: item.id,
      iv: item.iv,
      ciphertext: item.ciphertext,
      updatedAt: item.updatedAt,
      deleted: !!item.deleted,
      version: typeof item.version === "number" && Number.isSafeInteger(item.version) ? item.version : 0,
      dirty: true,
    };
  });
  return {
    email: value.email,
    iterations: value.kdf.iterations,
    items,
  };
}
