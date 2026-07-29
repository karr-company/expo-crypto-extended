import Constants from "expo-constants";
import {
  AESEncryptionKey,
  AESSealedData,
  aesDecryptAsync,
  aesEncryptAsync,
} from "expo-crypto";

import { DEFAULT_SALT, DEFAULT_INFO } from "./ExpoCryptoExtended.constants";
import type {
  DecryptParams,
  EncryptedPayload,
  EncryptedPayloadWithNonce,
  EncryptParams,
  EncryptWithNonceParams,
  HkdfSaltInfo,
} from "./ExpoCryptoExtended.types";
import {
  computeSharedSecret,
  generateKeyPair,
  hkdfSha256,
  getHkdfInfo as internalGetHkdfInfo,
} from "./ExpoCryptoExtendedModule";
export * from "./ExpoCryptoExtended.types";

export {
  aesGcmDecrypt,
  computeSharedSecret,
  generateKeyPair,
  hkdfSha256,
} from "./ExpoCryptoExtendedModule";

// Type assertion for expo-crypto static methods not exposed in TypeScript declarations.
type AESKeyConstructor = {
  import(bytes: Uint8Array): Promise<AESEncryptionKey>;
  import(
    hexString: string,
    encoding: "hex" | "base64",
  ): Promise<AESEncryptionKey>;
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
export function encrypt(params: EncryptParams): Promise<EncryptedPayload>;
/**
 * Encrypts plaintext using ephemeral X25519 ECDH + HKDF-SHA256 + AES-256-GCM.
 * Returns a payload with the nonce stored as an explicit field, separate from {@link EncryptedPayloadWithNonce.ciphertext}.
 */
export function encrypt(
  params: EncryptWithNonceParams,
): Promise<EncryptedPayloadWithNonce>;
export async function encrypt(
  params: EncryptParams | EncryptWithNonceParams,
): Promise<EncryptedPayload | EncryptedPayloadWithNonce> {
  const mSalt =
    params.salt ||
    Constants.expoConfig?.extra?.ExpoCryptoExtended.salt ||
    DEFAULT_SALT;
  const mInfo =
    params.info ||
    Constants.expoConfig?.extra?.ExpoCryptoExtended.info ||
    DEFAULT_INFO;
  const ephemeral = await generateKeyPair();

  const sharedSecret = await computeSharedSecret(
    ephemeral.privateKey,
    params.recipientPublicKey,
  );

  const aesKeyBase64 = await hkdfSha256({
    ikmBase64: sharedSecret,
    salt: mSalt,
    info: mInfo,
    keyLength: 32,
  });
  const key = await AESKey.import(aesKeyBase64, "base64");

  const plaintextBase64 = encodeBase64(
    new TextEncoder().encode(params.plaintext),
  );
  const sealed = (await aesEncryptAsync(
    plaintextBase64,
    key,
  )) as unknown as SealedDataMethods;

  if ("withNonce" in params && params.withNonce) {
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
export async function decrypt({
  payload,
  recipientPrivateKey,
  salt,
  info,
}: DecryptParams): Promise<string> {
  const mSalt =
    salt ||
    Constants.expoConfig?.extra?.ExpoCryptoExtended.salt ||
    DEFAULT_SALT;
  const mInfo =
    info ||
    Constants.expoConfig?.extra?.ExpoCryptoExtended.info ||
    DEFAULT_INFO;
  const sharedSecret = await computeSharedSecret(
    recipientPrivateKey,
    payload.ephemeralPublicKey,
  );

  const aesKeyBase64 = await hkdfSha256({
    ikmBase64: sharedSecret,
    salt: mSalt,
    info: mInfo,
    keyLength: 32,
  });
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
    sealed = AESSealed.fromCombined(decodeBase64(payload.ciphertext));
  }

  const decryptedBase64 = await aesDecryptAsync(sealed, key, {
    output: "base64",
  });

  return new TextDecoder().decode(decodeBase64(decryptedBase64));
}

/**
 * Get HKDF info for debugging
 */
export async function getHkdfInfo(): Promise<HkdfSaltInfo> {
  return await internalGetHkdfInfo();
}

function encodeBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function decodeBase64(base64: string): Uint8Array {
  const normalized =
    base64.trim().replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (base64.trim().length % 4)) % 4);

  return Uint8Array.from(atob(normalized), (c) => c.charCodeAt(0));
}
