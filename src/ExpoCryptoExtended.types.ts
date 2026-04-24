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
