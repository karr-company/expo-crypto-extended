import { NativeModule, requireNativeModule } from "expo";
import { X25519KeyPair } from "./ExpoCryptoExtended.types";

declare class ExpoCryptoExtendedModule extends NativeModule {
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

export function hkdfSha256(
  ikmBase64: string,
  salt: string,
  info: string,
  keyLength: number,
): Promise<string> {
  return nativeModule.hkdfSha256(ikmBase64, salt, info, keyLength);
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
