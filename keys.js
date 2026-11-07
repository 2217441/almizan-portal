// The key rules shared by encrypt.mjs and person.sh (Node), the login page and
// the service worker (ADR-100). A published file is named by an HMAC of its
// site path, so the host sees neither content nor titles.
//
// gate.json holds one slot per reader: the site's keys, and the keys of the
// papers that reader may open, sealed under a key derived from their
// passphrase. The browser keeps only that derived key, and opens its slot
// again from gate.json, so a publish that changes the site's keys signs no one
// out, and a reader whose slot is gone opens nothing.
globalThis.gate = {
  // OWASP's 2023 floor for PBKDF2-HMAC-SHA256. The ciphertext is public, so
  // this and the passphrase's length are all that stand against offline guessing.
  ITERATIONS: 600000,

  hex(bytes) { return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, '0')).join(''); },
  unhex(text) { return Uint8Array.from(text.match(/../g) ?? [], (h) => parseInt(h, 16)); },

  // A reader's passphrase as the 32 bytes that open their slot.
  async passKey(password, salt) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: this.ITERATIONS }, base, 256));
  },

  // Every key the site seals with is drawn from one secret, by name: "site",
  // "name", and "paper:<path under docs/>".
  async subkey(root, label) {
    const key = await crypto.subtle.importKey('raw', root, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(label)));
  },

  aesKey(raw, use) { return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, use); },
  macKey(raw) { return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); },

  // The first slot of gate.json that opens under this key, as the keys it
  // holds, or null when none does: a wrong passphrase, or a reader removed.
  async openSlot(wrap, { slots }) {
    for (const slot of slots) {
      const bytes = this.unhex(slot);
      let text;
      try {
        text = new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, 12) }, wrap, bytes.subarray(12)));
      } catch {
        continue;
      }
      const { name, site, mac, papers } = JSON.parse(text);
      return {
        name,
        aes: await this.aesKey(this.unhex(site), ['decrypt']),
        mac: await this.macKey(this.unhex(mac)),
        papers: await Promise.all(Object.entries(papers).map(async ([prefix, key]) => [prefix, await this.aesKey(this.unhex(key), ['decrypt'])])),
      };
    }
    return null;
  },

  // A path as bytes: what a file is named from, and what its ciphertext is
  // bound to, so a sealed file opens only at the address it was sealed for.
  bytes(path) { return new TextEncoder().encode(path.normalize('NFC')); },

  async nameFor(mac, path) {
    return this.hex(new Uint8Array(await crypto.subtle.sign('HMAC', mac, this.bytes(path)), 0, 16));
  },

  // Browser only. The key is stored as a non-extractable CryptoKey, so the
  // passphrase itself is never kept.
  store(mode, run) {
    return new Promise((resolve, reject) => {
      const open = indexedDB.open('gate', 1);
      open.onupgradeneeded = () => open.result.createObjectStore('keys');
      open.onerror = () => reject(open.error);
      open.onsuccess = () => {
        const tx = open.result.transaction('keys', mode);
        const request = run(tx.objectStore('keys'));
        tx.oncomplete = () => resolve(request.result);
        tx.onerror = () => reject(tx.error);
      };
    });
  },
  saveKey(key) { return this.store('readwrite', (s) => s.put(key, 'pass')); },
  loadKey() { return this.store('readonly', (s) => s.get('pass')); },
  // "current" held the one shared passphrase's keys before ADR-100.
  clearKeys() { return this.store('readwrite', (s) => { s.delete('current'); return s.delete('pass'); }); },
};
