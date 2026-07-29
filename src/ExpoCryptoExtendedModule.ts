import { NativeModule, requireNativeModule } from "expo";
import Constants from "expo-constants";

import { DEFAULT_INFO, DEFAULT_SALT } from "./ExpoCryptoExtended.constants";
import type {
  HkdfSaltInfo,
  HkdfSha256Params,
  X25519KeyPair,
} from "./ExpoCryptoExtended.types";

declare class ExpoCryptoExtendedModule extends NativeModule {
  generateKeyPair(): Promise<X25519KeyPair>;
  computeSharedSecret(
    privateKeyBase64: string,
    endPublicKeyBase64: string,
  ): Promise<string>;
  hkdfSha256(params: HkdfSha256Params): Promise<string>;
  aesGcmDecrypt(
    keyBase64: string,
    nonceBase64url: string,
    ciphertextBase64url: string,
  ): Promise<string>;
  getHkdfInfo(): Promise<HkdfSaltInfo>;
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

export function hkdfSha256({
  ikmBase64,
  salt,
  info,
  keyLength,
}: HkdfSha256Params): Promise<string> {
  // If the explicit function call provides a salt/info string, use it.
  // Otherwise, fall back onto the values injected by the config plugin, or hardcoded fallback defaults.
  const mSalt =
    salt ||
    Constants.expoConfig?.extra?.ExpoCryptoExtended.salt ||
    DEFAULT_SALT;
  const mInfo =
    info ||
    Constants.expoConfig?.extra?.ExpoCryptoExtended.info ||
    DEFAULT_INFO;

  return nativeModule.hkdfSha256({
    ikmBase64,
    salt: mSalt,
    info: mInfo,
    keyLength,
  });
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

export async function getHkdfInfo(): Promise<HkdfSaltInfo> {
  return nativeModule.getHkdfInfo();
}
