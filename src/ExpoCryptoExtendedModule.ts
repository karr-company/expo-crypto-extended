import { NativeModule, requireNativeModule } from "expo";
import { X25519KeyPair } from "./ExpoCryptoExtended.types";

declare class ExpoCryptoExtendedModule extends NativeModule {
  //  Tell TypeScript that the native module now exposes these fallback constants
  FALLBACK_SALT?: string;
  FALLBACK_INFO?: string;

  generateKeyPair(): Promise<X25519KeyPair>;
  computeSharedSecret(
    privateKeyBase64: string,
    endPublicKeyBase64: string,
  ): Promise<string>;
  hkdfSha256(
    ikmBase64: string,
    salt: string,
    info: string,
    keyLength: number,
  ): Promise<string>;
  aesGcmDecrypt(
    keyBase64: string,
    nonceBase64url: string,
    ciphertextBase64url: string,
  ): Promise<string>;
}

// This call loads the native module object from the JSI.
const nativeModule =
  requireNativeModule<ExpoCryptoExtendedModule>("ExpoCryptoExtended");

export function generateKeyPair(): Promise<X25519KeyPair> {
  return nativeModule.generateKeyPair();
}

export function computeSharedSecret(
  privateKeyBase64: string,
  endPublicKeyBase64: string,
): Promise<string> {
  return nativeModule.computeSharedSecret(privateKeyBase64, endPublicKeyBase64);
}

// 🎯 This is the only function block that changes behavior!
export function hkdfSha256(
  ikmBase64: string,
  salt: string,
  info: string,
  keyLength: number,
): Promise<string> {
  // If the explicit function call provides a salt/info string, use it.
  // Otherwise, fall back onto the values injected by the config plugin, or hardcoded fallback defaults.
  const finalSalt = salt || nativeModule.FALLBACK_SALT || "karr-e2e-v1-salt";
  const finalInfo = info || nativeModule.FALLBACK_INFO || "karr-e2e-v1-aes-gcm-key";

  return nativeModule.hkdfSha256(ikmBase64, finalSalt, finalInfo, keyLength);
}

export function aesGcmDecrypt(
  keyBase64: string,
  nonceBase64url: string,
  ciphertextBase64url: string,
): Promise<string> {
  return nativeModule.aesGcmDecrypt(
    keyBase64,
    nonceBase64url,
    ciphertextBase64url,
  );
}