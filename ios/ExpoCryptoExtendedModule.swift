import ExpoModulesCore
import CryptoKit

struct X25519KeyPair: Record {
  @Field var publicKey: String = ""
  @Field var privateKey: String = ""
}

public class ExpoCryptoExtendedModule: Module {

  public func definition() -> ModuleDefinition {
    Name("ExpoCryptoExtended")
    
    AsyncFunction("generateKeyPair") { (promise: Promise) in
      let privateKey = Curve25519.KeyAgreement.PrivateKey()
      let publicKey = privateKey.publicKey
      let keyPair = X25519KeyPair(
        publicKey: publicKey.rawRepresentation.base64EncodedString(),
        privateKey: privateKey.rawRepresentation.base64EncodedString()
      )
      promise.resolve(keyPair)
      return
    }

    AsyncFunction("computeSharedSecret") { (privateKeyB64: String,
                                            endPublicKeyB64: String,
                                            promise: Promise) in
      guard let privateKeyData = Data(base64Encoded: privateKeyB64),
            let endPublicKeyData = Data(base64Encoded: endPublicKeyB64) else {
        promise.reject(Exception(name: "InvalidKey", description: "Invalid base64 key"))
        return
      }
      
      let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
      let endPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: endPublicKeyData)
      
      let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: endPublicKey)
      
      // Return raw bytes as base64
      let s = sharedSecret.withUnsafeBytes { Data($0).base64EncodedString() }
      promise.resolve(s)
      return
    }

    AsyncFunction("hkdfSha256") { (ikmB64: String,
                                   salt: String,
                                   info: String,
                                   keyLength: Int,
                                   promise: Promise) in
      guard let ikmData = Data(base64Encoded: ikmB64) else {
        promise.reject(Exception(name: "InvalidKey", description: "Invalid base64 IKM"))
        return
      }

      let saltData = Data(salt.utf8)
      let infoData = Data(info.utf8)
      let ikm = SymmetricKey(data: ikmData)

      let derived = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: ikm,
        salt: saltData,
        info: infoData,
        outputByteCount: keyLength
      )

      let derivedB64 = derived.withUnsafeBytes { Data($0).base64EncodedString() }
      promise.resolve(derivedB64)
      return
    }

    AsyncFunction("aesGcmDecrypt") { (keyB64: String,
                                      nonceB64url: String,
                                      ciphertextB64url: String,
                                      promise: Promise) in
      guard let keyData = Data(base64Encoded: keyB64) else {
        promise.reject(Exception(name: "InvalidKey", description: "Invalid base64 AES key"))
        return
      }

      guard let nonceData = decodeBase64url(nonceB64url),
            let combinedData = decodeBase64url(ciphertextB64url) else {
        promise.reject(Exception(name: "InvalidInput", description: "Invalid base64url nonce or ciphertext"))
        return
      }

      guard combinedData.count > 16 else {
        promise.reject(Exception(name: "InvalidInput", description: "Ciphertext too short to contain auth tag"))
        return
      }

      let cipherBytes = combinedData.prefix(combinedData.count - 16)
      let tagBytes = combinedData.suffix(16)

      do {
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: cipherBytes, tag: tagBytes)
        let plainData = try AES.GCM.open(sealedBox, using: SymmetricKey(data: keyData))

        guard let plaintext = String(data: plainData, encoding: .utf8) else {
          promise.reject(Exception(name: "DecodingError", description: "Decrypted bytes are not valid UTF-8"))
          return
        }
        promise.resolve(plaintext)
      } catch {
        promise.reject(Exception(name: "DecryptionFailed", description: error.localizedDescription))
      }
      return
    }
  }
}

// Decodes a base64url string (RFC 4648 §5) into Data.
// Converts `-` -> `+`, `_` -> `/` and adds `=` padding.
private func decodeBase64url(_ base64url: String) -> Data? {
  var base64 = base64url
    .replacingOccurrences(of: "-", with: "+")
    .replacingOccurrences(of: "_", with: "/")
  let remainder = base64.count % 4
  if remainder != 0 {
    base64 += String(repeating: "=", count: 4 - remainder)
  }
  return Data(base64Encoded: base64)
}
