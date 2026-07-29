export interface X25519KeyPair {
  publicKey: string; // base64
  privateKey: string; // base64
}

/**
 * Encrypted payload where the nonce is embedded within {@link ciphertext} (combined format: nonce + ciphertext + tag).
 */
export interface EncryptedPayload {
  /** Base64-encoded AES-GCM sealed data (nonce + ciphertext + tag, combined) */
  ciphertext: string;
  /** Base64-encoded ephemeral X25519 public key used for key agreement */
  ephemeralPublicKey: string;
}

/**
 * Encrypted payload where the nonce is stored as an explicit, separate field.
 * {@link ciphertext} contains only the ciphertext + authentication tag (no nonce prefix).
 */
export interface EncryptedPayloadWithNonce {
  /** Base64-encoded AES-GCM nonce (IV) */
  nonce: string;
  /** Base64-encoded AES-GCM ciphertext + authentication tag */
  ciphertext: string;
  /** Base64-encoded ephemeral X25519 public key used for key agreement */
  ephemeralPublicKey: string;
}

/**
 * Parameters for key derivation using HKDF-SHA256.
 */
export interface HkdfSha256Params {
  /** Base64-encoded HKDF input key material */
  ikmBase64: string;
  /** Output key length in bytes */
  keyLength: number;
  /**
   * Optional salt value
   * @default "karr-e2e-v1-salt" or value passed to plugin in app config
   */
  salt?: string;
  /** Optional info value
   * @default "karr-e2e-v1-aes-gcm-key" or value passed to plugin in app config
   */
  info?: string;
}

/** Salt and info values for HKDF */
export interface HkdfSaltInfo {
  /** Salt value */
  salt: string;
  /** Info value */
  info: string;
}

/**
 * Parameters for encryption using AES-GCM.
 */
export interface EncryptParams {
  /** Data to encrypt */
  plaintext: string;
  /** Base64-encoded X25519 ephemeral public key */
  recipientPublicKey: string;
  /** Optional salt value
   * @default "karr-e2e-v1-salt" or value passed to plugin in app config
   */
  salt?: string;
  /** Optional info value
   * @default "karr-e2e-v1-aes-gcm-key" or value passed to plugin in app config
   */
  info?: string;
}

/**
 * Parameters for encryption using AES-GCM with nonce.
 */
export interface EncryptWithNonceParams extends EncryptParams {
  withNonce: boolean;
}

export interface DecryptParams {
  /** Base64-encoded AES-GCM ciphertext + authentication tag */
  payload: EncryptedPayload | EncryptedPayloadWithNonce;
  /** Base64-encoded X25519 private key */
  recipientPrivateKey: string;
  /** Optional salt value
   * @default "karr-e2e-v1-salt" or value passed to plugin in app config
   */
  salt?: string;
  /** Optional info value
   * @default "karr-e2e-v1-aes-gcm-key" or value passed to plugin in app config
   */
  info?: string;
}
