// One key derivation and one naming rule, loaded by encrypt.mjs (Node), the
// login page and the service worker. A published file is named by an HMAC of
// its site path, so the host sees neither content nor titles.
globalThis.gate = {
  // OWASP's 2023 floor for PBKDF2-HMAC-SHA256. The ciphertext is public, so
  // this and the passphrase length are all that stand against offline guessing.
  ITERATIONS: 600000,
  CHECK: '\0check',

  async deriveKeys(password, salt) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: this.ITERATIONS }, base, 512));
    return {
      aes: await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']),
      mac: await crypto.subtle.importKey('raw', bits.slice(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']),
    };
  },

  // A path as bytes: what a file is named from, and what its ciphertext is
  // bound to, so a sealed file opens only at the address it was sealed for.
  bytes(path) { return new TextEncoder().encode(path.normalize('NFC')); },

  async nameFor(mac, path) {
    const sig = await crypto.subtle.sign('HMAC', mac, this.bytes(path));
    return Array.from(new Uint8Array(sig, 0, 16), (b) => b.toString(16).padStart(2, '0')).join('');
  },

  // Browser only. The keys are stored as non-extractable CryptoKey objects, so
  // the passphrase itself is never kept.
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
  saveKeys(keys) { return this.store('readwrite', (s) => s.put(keys, 'current')); },
  loadKeys() { return this.store('readonly', (s) => s.get('current')); },
  clearKeys() { return this.store('readwrite', (s) => s.delete('current')); },
};
