export const CONFLICT_ERROR = "The vault changed on the server. Pull and merge.";
export const EMPTY_ERROR = "Refusing to replace a non-empty vault with an empty one.";

export function conflictingIds(existing, incoming) {
  const versions = new Map(existing.map((item) => [item.id, item.version || 0]));
  const ids = [];
  for (const item of incoming) {
    const current = versions.has(item.id) ? versions.get(item.id) : 0;
    if (current !== item.baseVersion) ids.push(item.id);
  }
  return ids;
}

/** True when applying incoming would leave no live entries and some exist now. */
export function leavesVaultEmpty(existing, incoming) {
  const live = new Set(existing.filter((item) => !item.deleted).map((item) => item.id));
  if (live.size === 0) return false;
  for (const item of incoming) {
    if (item.deleted) live.delete(item.id);
    else live.add(item.id);
  }
  return live.size === 0;
}

/**
 * Last-writer-wins by updatedAt. Equal timestamps keep a tombstone so a delete
 * is never resurrected by an older or simultaneous live copy.
 * When local content wins, the stored version becomes the max of both sides
 * so the next push uses the server's current version as baseVersion.
 */
export function chooseEntry(local, remote, incomingDirty = false) {
  if (local.updatedAt !== remote.updatedAt) {
    if (remote.updatedAt > local.updatedAt) return { ...remote, dirty: incomingDirty };
    return {
      ...local,
      version: Math.max(local.version || 0, remote.version || 0),
      dirty: !!local.dirty,
    };
  }
  if (!!local.deleted !== !!remote.deleted) {
    if (remote.deleted) return { ...remote, dirty: incomingDirty };
    return {
      ...local,
      version: Math.max(local.version || 0, remote.version || 0),
      dirty: !!local.dirty,
    };
  }
  if (local.dirty && !incomingDirty) {
    return {
      ...local,
      version: Math.max(local.version || 0, remote.version || 0),
      dirty: true,
    };
  }
  if (incomingDirty && local.dirty) {
    return {
      ...local,
      version: Math.max(local.version || 0, remote.version || 0),
      dirty: true,
    };
  }
  return { ...remote, dirty: incomingDirty };
}

export function mergeEntries(local, remote, { incomingDirty = false } = {}) {
  const map = new Map();
  for (const entry of local) map.set(entry.id, { ...entry });
  for (const entry of remote) {
    const current = map.get(entry.id);
    if (!current) {
      map.set(entry.id, { ...entry, dirty: incomingDirty || !!entry.dirty });
      continue;
    }
    map.set(entry.id, chooseEntry(current, entry, incomingDirty));
  }
  return [...map.values()];
}

/**
 * Refuse to upload when the local vault has no live entries and the server does,
 * unless every server entry has a newer-or-equal dirty tombstone (a real delete).
 */
export function uploadPlan(local, server) {
  const dirty = local.filter((item) => item.dirty && !item.unreadable);
  const serverLive = server.filter((item) => !item.deleted);
  const localLive = local.filter((item) => !item.deleted);
  if (localLive.length === 0 && serverLive.length > 0) {
    const covered = serverLive.every((item) =>
      local.some(
        (entry) =>
          entry.id === item.id &&
          entry.deleted &&
          entry.dirty &&
          !entry.unreadable &&
          entry.updatedAt >= item.updatedAt,
      ),
    );
    if (!covered) return { allow: false, confirmEmpty: false, items: [] };
    return { allow: true, confirmEmpty: true, items: dirty };
  }
  return { allow: true, confirmEmpty: false, items: dirty };
}

export function planSync(local, remote) {
  const merged = mergeEntries(local, remote);
  return { merged, plan: uploadPlan(merged, remote) };
}

/** In-memory model of the worker's optimistic write. Used by the node tests. */
export function applyIncoming(existing, incoming, confirmEmpty = false) {
  const conflicts = conflictingIds(existing, incoming);
  if (conflicts.length > 0) return { status: 409, error: CONFLICT_ERROR, items: existing };
  if (leavesVaultEmpty(existing, incoming) && !confirmEmpty) {
    return { status: 409, error: EMPTY_ERROR, items: existing };
  }
  const next = existing.map((item) => ({ ...item }));
  const byId = new Map(next.map((item) => [item.id, item]));
  for (const item of incoming) {
    const stored = {
      id: item.id,
      iv: item.iv,
      ciphertext: item.ciphertext,
      updatedAt: item.updatedAt,
      deleted: !!item.deleted,
      version: item.baseVersion + 1,
    };
    const current = byId.get(item.id);
    if (current) Object.assign(current, stored);
    else {
      next.push(stored);
      byId.set(item.id, stored);
    }
  }
  return { status: 200, items: next };
}
