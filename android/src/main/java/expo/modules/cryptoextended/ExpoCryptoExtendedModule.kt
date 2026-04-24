package expo.modules.cryptoextended

import android.os.Build
import android.util.Base64
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.interfaces.XECPrivateKey
import java.security.interfaces.XECPublicKey
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPrivateKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class X25519KeyPair(
  @Field val publicKey: String = "",
  @Field val privateKey: String = ""
) : Record

class ExpoCryptoExtendedModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("ExpoCryptoExtended")

    AsyncFunction("generateKeyPair") { promise: Promise ->
      var publicKeyStr = ""
      var privateKeyStr = ""

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        try {
          val kpg = KeyPairGenerator.getInstance("X25519")
          val keyPair = kpg.generateKeyPair()

          val publicKey = keyPair.public as XECPublicKey
          val privateKey = keyPair.private as XECPrivateKey

          // Extract raw bytes
          val publicBytes = publicKey.u.toByteArray().takeLast(32).toByteArray()
          val privateBytes = privateKey.scalar.orElseThrow().takeLast(32).toByteArray()

          publicKeyStr = Base64.encodeToString(publicBytes, Base64.NO_WRAP)
          privateKeyStr = Base64.encodeToString(privateBytes, Base64.NO_WRAP)
        } catch (e: Exception) {
          promise.reject("ERR_KEYGEN", e.message, e)
          return@AsyncFunction
        }
      } else {
        try {
          if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
          }

          val kpg = KeyPairGenerator.getInstance("X25519", "BC")
          val keyPair = kpg.generateKeyPair()

          val publicKey = keyPair.public as PublicKey
          val privateKey = keyPair.private as PrivateKey

          // Extract raw bytes
          val publicBytes = publicKey.encoded
          val privateBytes = privateKey.encoded

          publicKeyStr = Base64.encodeToString(publicBytes, Base64.NO_WRAP)
          privateKeyStr = Base64.encodeToString(privateBytes, Base64.NO_WRAP)
        } catch (e: Exception) {
          promise.reject("ERR_KEYGEN", e.message, e)
          return@AsyncFunction
        }
      }

      val x25519KeyPair = X25519KeyPair(
        publicKey = publicKeyStr,
        privateKey = privateKeyStr
      )

      promise.resolve(x25519KeyPair)
      return@AsyncFunction
    }

    AsyncFunction("computeSharedSecret") {
      privateKeyBase64: String,
      endPublicKeyBase64: String,
      promise: Promise ->
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        try {
          val privateBytes = Base64.decode(privateKeyBase64, Base64.NO_WRAP)
          val endPublicBytes = Base64.decode(endPublicKeyBase64, Base64.NO_WRAP)

          val paramSpec = NamedParameterSpec.X25519

          // Reconstruct keys
          val keyFactory = KeyFactory.getInstance("X25519")
          val privateKeySpec = XECPrivateKeySpec(paramSpec, privateBytes)
          val privateKey = keyFactory.generatePrivate(privateKeySpec)

          val publicKeySpec = XECPublicKeySpec(paramSpec, BigInteger(1, endPublicBytes))
          val endPublicKey = keyFactory.generatePublic(publicKeySpec)

          // ECDH
          val keyAgreement = KeyAgreement.getInstance("X25519")
          keyAgreement.init(privateKey)
          keyAgreement.doPhase(endPublicKey, true)
          val sharedSecret = keyAgreement.generateSecret()

          promise.resolve(Base64.encodeToString(sharedSecret, Base64.NO_WRAP))
          return@AsyncFunction
        } catch (e: Exception) {
          promise.reject("ERR_ECDH", e.message, e)
          return@AsyncFunction
        }
      } else {
        try {
          if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
          }

          val privateBytes = Base64.decode(privateKeyBase64, Base64.NO_WRAP)
          val endPublicBytes = Base64.decode(endPublicKeyBase64, Base64.NO_WRAP)

          // Reconstruct keys
          val keyFactory = KeyFactory.getInstance("X25519", "BC")
          val privateKeySpec = SecretKeySpec(privateBytes, "X25519")
          val privateKey = keyFactory.generatePrivate(privateKeySpec)

          val publicKeySpec = SecretKeySpec(endPublicBytes, "X25519")
          val endPublicKey = keyFactory.generatePublic(publicKeySpec)

          // ECDH
          val keyAgreement = KeyAgreement.getInstance("X25519", "BC")
          keyAgreement.init(privateKey)
          keyAgreement.doPhase(endPublicKey, true)
          val sharedSecret = keyAgreement.generateSecret()

          promise.resolve(Base64.encodeToString(sharedSecret, Base64.NO_WRAP))
          return@AsyncFunction
        } catch (e: Exception) {
          promise.reject("ERR_ECDH", e.message, e)
          return@AsyncFunction
        }
      }
    }

    AsyncFunction("hkdfSha256") { ikmBase64: String,
                                   salt: String,
                                   info: String,
                                   keyLength: Int,
                                   promise: Promise ->
      try {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
          Security.addProvider(BouncyCastleProvider())
        }

        val ikmBytes = Base64.decode(ikmBase64, Base64.NO_WRAP)
        val saltBytes = salt.toByteArray(Charsets.UTF_8)
        val infoBytes = info.toByteArray(Charsets.UTF_8)

        val generator = HKDFBytesGenerator(org.bouncycastle.crypto.digests.SHA256Digest())
        generator.init(HKDFParameters(ikmBytes, saltBytes, infoBytes))

        val out = ByteArray(keyLength)
        generator.generateBytes(out, 0, keyLength)

        promise.resolve(Base64.encodeToString(out, Base64.NO_WRAP))
        return@AsyncFunction
      } catch (e: Exception) {
        promise.reject("ERR_HKDF", e.message, e)
        return@AsyncFunction
      }
    }

    AsyncFunction("aesGcmDecrypt") { keyBase64: String,
                                     nonceBase64url: String,
                                     ciphertextBase64url: String,
                                     promise: Promise ->
      try {
        val keyBytes = Base64.decode(keyBase64, Base64.NO_WRAP)
        val nonceBytes = Base64.decode(nonceBase64url, Base64.URL_SAFE or Base64.NO_WRAP)
        val combined = Base64.decode(ciphertextBase64url, Base64.URL_SAFE or Base64.NO_WRAP)

        if (combined.size <= 16) {
          promise.reject("ERR_AES_GCM", "Ciphertext too short to contain auth tag", null)
          return@AsyncFunction
        }

        // JCA AES/GCM/NoPadding expects ciphertext with tag appended — pass combined as-is
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(keyBytes, "AES")
        val gcmSpec = GCMParameterSpec(128, nonceBytes)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

        val plainBytes = cipher.doFinal(combined)
        promise.resolve(String(plainBytes, Charsets.UTF_8))
        return@AsyncFunction
      } catch (e: Exception) {
        promise.reject("ERR_AES_GCM", e.message, e)
        return@AsyncFunction
      }
    }
  }
}
