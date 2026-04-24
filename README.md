# @karr-company/expo-crypto-extended

![npm](https://img.shields.io/npm/v/@karr-company/expo-crypto-extended.svg)
![License](https://img.shields.io/npm/l/@karr-company/expo-crypto-extended.svg)

Cross-platform Expo module for modern cryptographic primitives used in end-to-end encrypted flows.

This package provides a unified API for:
- X25519 ECDH key agreement
- HKDF-SHA256 key derivation
- AES-256-GCM decryption (authenticated decryption)

## Why This Module Exists

`expo-crypto` is useful for hashing and digest operations, but many secure messaging and key-agreement workflows also need native key exchange, HKDF, and AEAD handling.

This module fills that gap with one API surface for Expo apps.

## Requirements

- Expo SDK 55+
- React Native with Expo Modules support
- Development builds (not Expo Go)

Important: This module depends on Expo Crypto v55 (`expo-crypto@^55.x`).

## Installation

Install the package:

```bash
npm install @karr-company/expo-crypto-extended
```

or

```bash
yarn add @karr-company/expo-crypto-extended
```

Then rebuild your native app:

```bash
npx expo prebuild
npx expo run:ios
npx expo run:android
```

## API

### `generateKeyPair()`

Generates an X25519 keypair.

Returns:

```ts
Promise<{
  publicKey: string; // base64
  privateKey: string; // base64
}>
```

### `computeSharedSecret(privateKeyBase64, endPublicKeyBase64)`

Computes X25519 shared secret from your private key and the other party's public key.

Returns:

```ts
Promise<string> // base64 shared secret
```

### `hkdfSha256(ikmBase64, salt, info, keyLength)`

Derives keying material using HKDF-SHA256.

Parameters:
- `ikmBase64`: Input key material in base64
- `salt`: UTF-8 string salt
- `info`: UTF-8 context info
- `keyLength`: output length in bytes

Returns:

```ts
Promise<string> // base64 derived key
```

### `aesGcmDecrypt(keyBase64, nonceBase64url, ciphertextBase64url)`

Performs AES-GCM authenticated decryption.

Parameters:
- `keyBase64`: AES key in base64 (32 bytes for AES-256)
- `nonceBase64url`: nonce/IV in base64url
- `ciphertextBase64url`: ciphertext+tag in base64url

Returns:

```ts
Promise<string> // UTF-8 plaintext
```

Notes:
- `ciphertextBase64url` must include the authentication tag.
- Decryption fails if tag validation fails.

## Usage Example

```ts
import {
  aesGcmDecrypt,
  computeSharedSecret,
  generateKeyPair,
  hkdfSha256,
} from "@karr-company/expo-crypto-extended";

async function demo() {
  const alice = await generateKeyPair();
  const bob = await generateKeyPair();

  // ECDH shared secret
  const shared = await computeSharedSecret(alice.privateKey, bob.publicKey);

  // Derive 32-byte AES key
  const aesKey = await hkdfSha256(shared, "salt-v1", "chat-message", 32);

  // Decrypt payload received from server/peer
  const plaintext = await aesGcmDecrypt(
    aesKey,
    "BASE64URL_NONCE",
    "BASE64URL_CIPHERTEXT_WITH_TAG",
  );

  return plaintext;
}
```

## Web Compatibility

Web support relies on Web Crypto and is only available in secure contexts:
- HTTPS origins
- localhost

If your target environment is not a secure context, you can implement crypto operations in an Expo Router API route and execute them server-side with Node Crypto:
- Expo Router API routes: https://docs.expo.dev/router/web/api-routes/
- Node Crypto: https://nodejs.org/api/crypto.html

Recommended server-side primitives:

```ts
//! - X25519 ECDH for key exchange (ephemeral keys per message)
//! - HKDF-SHA256 for key derivation
//! - AES-256-GCM for authenticated encryption
```

## Android Notes (BouncyCastle)

This module includes BouncyCastle for compatibility with older Android versions.

Dependency included by this module:

```gradle
implementation("org.bouncycastle:bcprov-jdk15to18:1.81")
```

Warning: BouncyCastle can cause Gradle dependency conflicts in some app dependency graphs.

Recommendation: use an Expo config plugin (or your existing build plugin stack) to enforce a single BouncyCastle version and resolve conflict errors consistently.

## Proguard / R8 Rules

If your app uses Proguard or R8 minification, include the following rules:

```pro
-keep class org.bouncycastle.** {*;}

# BouncyCastle LDAP/JNDI classes - not available on Android
-dontwarn javax.naming.**
-dontwarn org.bouncycastle.jce.provider.X509LDAPCertStoreSpi
-dontwarn org.bouncycastle.jce.provider.CrlCache
```

## Security Guidance

- Prefer ephemeral keypairs per message/session when possible.
- Never reuse AES-GCM nonces with the same key.
- Validate all input encoding at trust boundaries.
- Keep private keys out of logs and analytics.
- Consider platform secure storage for long-lived secrets.

## Error Handling

Typical error categories:
- Invalid base64/base64url input
- Invalid key length
- AES-GCM authentication failure
- Unsupported platform/runtime crypto capabilities

Treat decryption failures as security-sensitive and fail closed.

## Known Limitations

- This module currently exposes AES-GCM decryption only (no encryption helper API).
- Web behavior depends on browser Web Crypto support and secure-context restrictions.

## Development

Build module:

```bash
npm run build
```

Lint:

```bash
npm run lint
```

Run tests:

```bash
npm test
```

## Contributing

Issues and PRs are welcome:
https://github.com/karr-company/expo-crypto-extended/issues

## License

MIT
