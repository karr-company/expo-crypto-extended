export * from "./ExpoCryptoExtended.types";
import {
  AESEncryptionKey,
  AESSealedData,
  aesDecryptAsync,
  aesEncryptAsync,
} from "expo-crypto";
import type { EncryptedPayload, EncryptedPayloadWithNonce } from "./ExpoCryptoExtended.types";
import {
  computeSharedSecret,
  generateKeyPair,
  hkdfSha256,
} from "./ExpoCryptoExtendedModule";

export {
  aesGcmDecrypt,
  computeSharedSecret,
  generateKeyPair,
  hkdfSha256,
} from "./ExpoCryptoExtendedModule";

// Type assertion for expo-crypto static methods not exposed in TypeScript declarations.
type AESKeyConstructor = {
  import(bytes: Uint8Array): Promise<AESEncryptionKey>;
  import(hexString: string, encoding: "hex" | "base64"): Promise<AESEncryptionKey>;
};

const AESKey = AESEncryptionKey as unknown as AESKeyConstructor;

type AESSealedConstructor = {
  fromCombined(combined: string | Uint8Array | ArrayBuffer): AESSealedData;
};

const AESSealed = AESSealedData as unknown as AESSealedConstructor;

interface SealedDataMethods {
  combined(encoding?: "bytes"): Promise<Uint8Array>;
  combined(encoding: "base64"): Promise<string>;
  iv(encoding?: "bytes"): Promise<Uint8Array>;
  iv(encoding: "base64"): Promise<string>;
}

/**
 * Encrypts plaintext using ephemeral X25519 ECDH + HKDF-SHA256 + AES-256-GCM.
 * Returns a combined payload where the nonce is embedded within {@link EncryptedPayload.ciphertext}.
 */
export function encrypt(
  plaintext: string,
  recipientPublicKey: string,
  salt: string,
  info: string,
): Promise<EncryptedPayload>;
/**
 * Encrypts plaintext using ephemeral X25519 ECDH + HKDF-SHA256 + AES-256-GCM.
 * Returns a payload with the nonce stored as an explicit field, separate from {@link EncryptedPayloadWithNonce.ciphertext}.
 */
export function encrypt(
  plaintext: string,
  recipientPublicKey: string,
  salt: string,
  info: string,
  options: { withNonce: true },
): Promise<EncryptedPayloadWithNonce>;
export async function encrypt(
  plaintext: string,
  recipientPublicKey: string,
  salt: string,
  info: string,
  options?: { withNonce?: boolean },
): Promise<EncryptedPayload | EncryptedPayloadWithNonce> {
  const ephemeral = await generateKeyPair();

  const sharedSecret = await computeSharedSecret(
    ephemeral.privateKey,
    recipientPublicKey,
  );

  const aesKeyBase64 = await hkdfSha256(sharedSecret, salt, info, 32);
  const key = await AESKey.import(aesKeyBase64, "base64");

  const plaintextBase64 = encodeBase64(new TextEncoder().encode(plaintext));
  const sealed = (await aesEncryptAsync(
    plaintextBase64,
    key,
  )) as unknown as SealedDataMethods;

  if (options?.withNonce) {
    // Split combined payload into nonce and ciphertext+tag for APIs that transport nonce separately.
    const combinedBytes = await sealed.combined();
    const ivBytes = await sealed.iv();
    const ciphertextAndTag = combinedBytes.slice(ivBytes.length);
    return {
      nonce: encodeBase64(ivBytes),
      ciphertext: encodeBase64(ciphertextAndTag),
      ephemeralPublicKey: ephemeral.publicKey,
    };
  }

  return {
    ciphertext: await sealed.combined("base64"),
    ephemeralPublicKey: ephemeral.publicKey,
  };
}

/**
 * Decrypts a payload produced by {@link encrypt}.
 * Accepts both the combined format ({@link EncryptedPayload}) and the
 * explicit-nonce format ({@link EncryptedPayloadWithNonce}).
 */
export async function decrypt(
  payload: EncryptedPayload | EncryptedPayloadWithNonce,
  recipientPrivateKey: string,
  salt: string,
  info: string,
): Promise<string> {
  const sharedSecret = await computeSharedSecret(
    recipientPrivateKey,
    payload.ephemeralPublicKey,
  );

  const aesKeyBase64 = await hkdfSha256(sharedSecret, salt, info, 32);
  const key = await AESKey.import(aesKeyBase64, "base64");

  let sealed: AESSealedData;
  if ("nonce" in payload) {
    // Rebuild combined representation expected by expo-crypto from nonce + ciphertext/tag fields.
    const ivBytes = decodeBase64(payload.nonce);
    const ciphertextBytes = decodeBase64(payload.ciphertext);
    const combined = new Uint8Array(ivBytes.length + ciphertextBytes.length);
    combined.set(ivBytes);
    combined.set(ciphertextBytes, ivBytes.length);
    sealed = AESSealed.fromCombined(combined);
  } else {
    sealed = AESSealed.fromCombined(payload.ciphertext);
  }

  const decryptedBase64 = await aesDecryptAsync(sealed, key, {
    output: "base64",
  });

  return new TextDecoder().decode(decodeBase64(decryptedBase64));
}

function encodeBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function decodeBase64(base64: string): Uint8Array {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}
