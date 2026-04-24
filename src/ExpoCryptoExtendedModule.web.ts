import { X25519KeyPair } from "./ExpoCryptoExtended.types";

export function generateKeyPair(): Promise<X25519KeyPair> {
  return new Promise((resolve) => {
    const subtle = crypto.subtle;
    subtle
      .generateKey({ name: "X25519", namedCurve: "X25519" }, true, [
        "deriveBits",
      ])
      .then((keyPair) =>
        Promise.all([
          subtle.exportKey("raw", keyPair.publicKey),
          subtle.exportKey("raw", keyPair.privateKey),
        ]).then(([publicKey, privateKey]) => {
          resolve({
            publicKey: bytesToBase64(new Uint8Array(publicKey)),
            privateKey: bytesToBase64(new Uint8Array(privateKey)),
          });
        }),
      );
  });
}

export function computeSharedSecret(
  privateKeyBase64: string,
  endPublicKeyBase64: string,
): Promise<string> {
  return new Promise((resolve) => {
    const subtle = crypto.subtle;

    const sharedSecretPromise = Promise.all([
      subtle.importKey(
        "raw",
        base64ToBytes(privateKeyBase64),
        { name: "X25519" },
        false,
        ["deriveBits"],
      ),
      subtle.importKey(
        "raw",
        base64ToBytes(endPublicKeyBase64),
        { name: "X25519" },
        false,
        [],
      ),
    ]).then(([privateKey, publicKey]) =>
      subtle.deriveBits({ name: "X25519", public: publicKey }, privateKey, 256),
    );

    sharedSecretPromise.then((sharedSecret) => {
      resolve(bytesToBase64(new Uint8Array(sharedSecret)));
    });
  });
}

export async function hkdfSha256(
  ikmBase64: string,
  salt: string,
  info: string,
  keyLength: number,
): Promise<string> {
  const subtle = crypto.subtle;

  const ikmBytes = base64ToBytes(ikmBase64);
  const saltBytes = new TextEncoder().encode(salt);
  const infoBytes = new TextEncoder().encode(info);

  const baseKey = await subtle.importKey("raw", ikmBytes, "HKDF", false, [
    "deriveBits",
  ]);

  const derivedBits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: saltBytes, info: infoBytes },
    baseKey,
    keyLength * 8,
  );

  return bytesToBase64(new Uint8Array(derivedBits));
}

export async function aesGcmDecrypt(
  keyBase64: string,
  nonceBase64url: string,
  ciphertextBase64url: string,
): Promise<string> {
  const subtle = crypto.subtle;

  const keyBytes = base64ToBytes(keyBase64);
  const nonceBytes = base64urlToBytes(nonceBase64url);
  const combined = base64urlToBytes(ciphertextBase64url);

  if (combined.length <= 16) {
    throw new Error("Ciphertext too short to contain auth tag");
  }

  const aesKey = await subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  // SubtleCrypto AES-GCM expects ciphertext with tag appended — combined is already in that format
  const plainBuffer = await subtle.decrypt(
    { name: "AES-GCM", iv: nonceBytes, tagLength: 128 },
    aesKey,
    combined,
  );

  return new TextDecoder().decode(plainBuffer);
}

function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const raw = atob(b64);
  const buffer = new ArrayBuffer(raw.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < raw.length; i++) {
    bytes[i] = raw.charCodeAt(i);
  }
  return bytes;
}

function base64urlToBytes(b64url: string): Uint8Array<ArrayBuffer> {
  const b64 =
    b64url.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (b64url.length % 4)) % 4);
  return base64ToBytes(b64);
}

function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}
