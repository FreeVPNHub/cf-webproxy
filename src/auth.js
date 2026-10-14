// Per-isolate performance cache only: authentication results are never cached.
// A small LRU bound also limits retention of keys from previous configurations.
export function createHmacSigner(subtle = crypto.subtle, maxKeys = 4) {
  if (!Number.isInteger(maxKeys) || maxKeys < 1) throw new RangeError("invalid key cache limit");
  const keys = new Map();
  return async function hmac(keyBytes, data) {
    const bytes = new Uint8Array(keyBytes);
    // Exact key identity keeps bridge and session-signing domains separate and
    // ensures a changed PROXY_SECRET cannot accidentally reuse the old key.
    const id = Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
    let pending = keys.get(id);
    if (pending) keys.delete(id);
    else {
      pending = subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      pending.catch(() => {
        // A failed, evicted import must not remove a newer entry for this key.
        if (keys.get(id) === pending) keys.delete(id);
      });
    }
    keys.set(id, pending);
    if (keys.size > maxKeys) keys.delete(keys.keys().next().value);
    return new Uint8Array(await subtle.sign("HMAC", await pending, data));
  };
}

export const hmac = createHmacSigner();
