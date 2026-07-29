# @karr-company/expo-crypto-extended

![npm](https://img.shields.io/npm/v/@karr-company/expo-crypto-extended.svg)
![License](https://img.shields.io/npm/l/@karr-company/expo-crypto-extended.svg)

Cross-platform Expo module for X25519 ECDH, HKDF-SHA256 key derivation, and AES-256-GCM authenticated encryption/decryption.

Provides `encrypt()` / `decrypt()` wrappers that compose these primitives into a high-level AEAD interface, plus lower-level exports for custom protocols.

## Why This Module Exists

`expo-crypto` covers digests and basic encryption, but end-to-end encrypted messaging requires:
- **X25519 ECDH** — ephemeral key agreement
- **HKDF-SHA256** — key derivation with salt/info context
- **AES-256-GCM** — authenticated symmetric encryption

This module composes those primitives into a single `encrypt()`/`decrypt()` pair using an ephemeral X25519 key exchange + HKDF + AES-GCM, and also exposes each building block for custom use.

## Requirements

- Expo SDK 57+
- React Native with Expo Modules support
- Development builds (not Expo Go)

Depends on `expo-crypto@^57.x` and `expo-constants@~57.x`.

## Installation

```bash
npm install @karr-company/expo-crypto-extended
```

Then rebuild your native app:

```bash
npx expo prebuild
npx expo run:ios
npx expo run:android
```

## Configuration

### Option 1: Config Plugin (recommended)

Add the plugin to your `app.json` or `app.config.js` with HKDF salt and info values:

```json
{
  "expo": {
    "plugins": [
      [
        "@karr-company/expo-crypto-extended/app.plugin.js",
        {
          "salt": "my-app-salt",
          "info": "my-app-info"
        }
      ]
    ]
  }
}
```

The plugin injects these values into:
- **iOS**: `Info.plist` (`EXPO_CRYPTO_EXTENDED_SALT`, `EXPO_CRYPTO_EXTENDED_INFO`)
- **Android**: `AndroidManifest.xml` (meta-data entries)
- **Runtime**: `Constants.expoConfig.extra.ExpoCryptoExtended`

### Option 2: `extra` in app.json

If you prefer not to use the config plugin, set `extra.ExpoCryptoExtended` directly:

```json
{
  "expo": {
    "extra": {
      "ExpoCryptoExtended": {
        "salt": "my-app-salt",
        "info": "my-app-info"
      }
    }
  }
}
```

### Resolution order

When `salt`/`info` are omitted from a function call, the module resolves them in this order:
1. Explicit parameter (highest priority)
2. `Constants.expoConfig?.extra?.ExpoCryptoExtended` (from plugin or `extra` config)
3. Built-in defaults (`"karr-e2e-v1-salt"` / `"karr-e2e-v1-aes-gcm-key"`)

## API

### `encrypt(params)`

Performs ephemeral X25519 ECDH + HKDF-SHA256 + AES-256-GCM authenticated encryption.

Generates an ephemeral keypair per call, derives a symmetric key via HKDF from the shared secret, and encrypts with AES-256-GCM.

```ts
function encrypt(params: EncryptParams): Promise<EncryptedPayload>
function encrypt(params: EncryptWithNonceParams): Promise<EncryptedPayloadWithNonce>
```

#### EncryptParams

| Field | Type | Description |
|-------|------|-------------|
| `plaintext` | `string` | Data to encrypt (UTF-8) |
| `recipientPublicKey` | `string` | Base64-encoded X25519 public key of the recipient |
| `salt?` | `string` | HKDF salt (default: from plugin config or built-in) |
| `info?` | `string` | HKDF info (default: from plugin config or built-in) |
| `withNonce?` | `boolean` | When `true`, returns nonce as a separate field |

#### Return types

**`EncryptedPayload`** (combined — nonce embedded in ciphertext):
```ts
{
  ciphertext: string;       // base64 — nonce + ciphertext + tag
  ephemeralPublicKey: string; // base64
}
```

**`EncryptedPayloadWithNonce`** (explicit nonce — returned when `withNonce: true`):
```ts
{
  nonce: string;            // base64
  ciphertext: string;       // base64 — ciphertext + tag only
  ephemeralPublicKey: string; // base64
}
```

---

### `decrypt(params)`

Authenticated decryption of a payload produced by `encrypt()`. Accepts both payload formats.

```ts
function decrypt(params: DecryptParams): Promise<string>
```

#### DecryptParams

| Field | Type | Description |
|-------|------|-------------|
| `payload` | `EncryptedPayload \| EncryptedPayloadWithNonce` | Payload from `encrypt()` |
| `recipientPrivateKey` | `string` | Base64-encoded X25519 private key |
| `salt?` | `string` | HKDF salt (must match encryption) |
| `info?` | `string` | HKDF info (must match encryption) |

Returns the decrypted UTF-8 plaintext.

---

### `generateKeyPair()`

Generates an X25519 keypair.

```ts
function generateKeyPair(): Promise<X25519KeyPair>
```

```ts
{
  publicKey: string;  // base64
  privateKey: string; // base64
}
```

---

### `computeSharedSecret(privateKeyBase64, endPublicKeyBase64)`

Computes an X25519 shared secret.

```ts
function computeSharedSecret(
  privateKeyBase64: string,
  endPublicKeyBase64: string,
): Promise<string>  // base64 shared secret
```

---

### `hkdfSha256(params)`

Derives keying material using HKDF-SHA256.

```ts
function hkdfSha256(params: HkdfSha256Params): Promise<string>  // base64 derived key
```

| Field | Type | Description |
|-------|------|-------------|
| `ikmBase64` | `string` | Input key material (base64) |
| `keyLength` | `number` | Output length in bytes |
| `salt?` | `string` | HKDF salt |
| `info?` | `string` | HKDF context info |

---

### `aesGcmDecrypt(keyBase64, nonceBase64url, ciphertextBase64url)`

Low-level AES-256-GCM authenticated decryption.

```ts
function aesGcmDecrypt(
  keyBase64: string,
  nonceBase64url: string,
  ciphertextBase64url: string,
): Promise<string>  // UTF-8 plaintext
```

- `ciphertextBase64url` must include the 16-byte authentication tag appended.
- Decryption fails (throws) if tag validation fails.

---

### `getHkdfInfo()`

Reads the currently configured HKDF salt and info values from the app config (plugin or `extra.ExpoCryptoExtended`).

```ts
function getHkdfInfo(): Promise<HkdfSaltInfo>
```

```ts
{
  salt: string;
  info: string;
}
```

Useful for debugging or displaying the active configuration.

## Usage Examples

### High-level encrypt/decrypt

```ts
import { decrypt, encrypt, generateKeyPair } from "@karr-company/expo-crypto-extended";

async function sendEncryptedMessage(recipientPublicKey: string, message: string) {
  const payload = await encrypt({
    plaintext: message,
    recipientPublicKey,
  });
  // Send payload.ciphertext and payload.ephemeralPublicKey to recipient
  return payload;
}

async function receiveEncryptedMessage(
  myPrivateKey: string,
  payload: { ciphertext: string; ephemeralPublicKey: string },
) {
  const plaintext = await decrypt({
    payload,
    recipientPrivateKey: myPrivateKey,
  });
  return plaintext;
}
```

### With explicit nonce (nonce separated from ciphertext)

```ts
const payload = await encrypt({
  plaintext: "Hello",
  recipientPublicKey: alice.publicKey,
  withNonce: true,
});
// payload.nonce, payload.ciphertext, payload.ephemeralPublicKey
```

### Custom salt/info per call

```ts
const payload = await encrypt({
  plaintext: "Secret",
  recipientPublicKey: bob.publicKey,
  salt: "session-specific-salt",
  info: "session-specific-info",
});
```

### Low-level primitives

```ts
import {
  aesGcmDecrypt,
  computeSharedSecret,
  generateKeyPair,
  hkdfSha256,
} from "@karr-company/expo-crypto-extended";

const alice = await generateKeyPair();
const bob = await generateKeyPair();

const shared = await computeSharedSecret(alice.privateKey, bob.publicKey);

const aesKey = await hkdfSha256({
  ikmBase64: shared,
  salt: "my-salt",
  info: "my-info",
  keyLength: 32,
});

const plaintext = await aesGcmDecrypt(aesKey, nonce, ciphertextWithTag);
```

## Web Compatibility

Web support relies on Web Crypto and is only available in secure contexts:
- HTTPS origins
- localhost

If your target environment is not a secure context, implement crypto server-side with Node Crypto:
- [Expo Router API routes](https://docs.expo.dev/router/web/api-routes/)
- [Node Crypto](https://nodejs.org/api/crypto.html)

## Android Notes (BouncyCastle)

Includes BouncyCastle for X25519/HKDF on Android:

```gradle
implementation("org.bouncycastle:bcprov-jdk15to18:1.81")
```

BouncyCastle can cause Gradle dependency conflicts. Use the config plugin (or your build plugin stack) to enforce a single version.

## Proguard / R8 Rules

```pro
-keep class org.bouncycastle.** {*;}
-dontwarn javax.naming.**
-dontwarn org.bouncycastle.jce.provider.X509LDAPCertStoreSpi
-dontwarn org.bouncycastle.jce.provider.CrlCache
```

## Security Guidance

- Use ephemeral keypairs per message/session (`encrypt()` does this automatically).
- Never reuse an AES-GCM nonce with the same key.
- Validate all input encoding at trust boundaries.
- Keep private keys out of logs and analytics.
- Use platform secure storage (Keychain/Keystore) for long-lived keys.
- Treat decryption failures as security-sensitive and fail closed.

## Error Handling

Error categories:
- Invalid base64/base64url input
- Invalid key length
- AES-GCM authentication failure (tampered ciphertext)
- Unsupported platform/runtime crypto

## Known Limitations

- Web encryption not yet available (only native iOS/Android) — `encrypt()` and `decrypt()` are native-only.
- `aesGcmDecrypt` is exposed for low-layer use; prefer `encrypt()`/`decrypt()` for new integrations.
- Default salt/info values are hardcoded; configure via the plugin or `extra.ExpoCryptoExtended` for production.

## Development

```bash
npm run build
npm run lint
npm test
```

Example app:

```bash
cd example
npm run ios     # or android / web
```

## Contributing

Issues and PRs welcome:
https://github.com/karr-company/expo-crypto-extended/issues

## License

MIT
