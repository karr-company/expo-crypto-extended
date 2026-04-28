package expo.modules.cryptoextended

import android.util.Base64
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.records.Field
import expo.modules.kotlin.records.Record
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class X25519KeyPair(
  @Field val publicKey: String = "",
  @Field val privateKey: String = ""
) : Record

private const val BASE64_URL_FLAGS = Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING

private fun decodeBase64Compat(value: String): ByteArray {
  val trimmed = value.trim()

  return try {
    Base64.decode(trimmed, BASE64_URL_FLAGS)
  } catch (_: IllegalArgumentException) {
    Base64.decode(trimmed, Base64.NO_WRAP)
  }
}

class ExpoCryptoExtendedModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("ExpoCryptoExtended")

    AsyncFunction("generateKeyPair") { promise: Promise ->
      try {
        val gen = X25519KeyPairGenerator()
        gen.init(X25519KeyGenerationParameters(SecureRandom()))
        val keyPair = gen.generateKeyPair()

        val publicKey = keyPair.public as X25519PublicKeyParameters
        val privateKey = keyPair.private as X25519PrivateKeyParameters

        promise.resolve(
          X25519KeyPair(
            publicKey = Base64.encodeToString(publicKey.encoded, BASE64_URL_FLAGS),
            privateKey = Base64.encodeToString(privateKey.encoded, BASE64_URL_FLAGS)
          )
        )
      } catch (e: Exception) {
        promise.reject("ERR_KEYGEN", e.message, e)
      }
    }

    AsyncFunction("computeSharedSecret") {
      privateKeyBase64: String,
      endPublicKeyBase64: String,
      promise: Promise ->
      try {
        val privateBytes = decodeBase64Compat(privateKeyBase64)
        val publicBytes = decodeBase64Compat(endPublicKeyBase64)

        val privateKey = X25519PrivateKeyParameters(privateBytes, 0)
        val publicKey = X25519PublicKeyParameters(publicBytes, 0)

        val agreement = X25519Agreement()
        agreement.init(privateKey)
        val sharedSecret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(publicKey, sharedSecret, 0)

        promise.resolve(Base64.encodeToString(sharedSecret, Base64.NO_WRAP))
      } catch (e: Exception) {
        promise.reject("ERR_ECDH", e.message, e)
      }
    }

    AsyncFunction("hkdfSha256") { ikmBase64: String,
                                   salt: String,
                                   info: String,
                                   keyLength: Int,
                                   promise: Promise ->
      try {
        val ikmBytes = decodeBase64Compat(ikmBase64)
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
        val keyBytes = decodeBase64Compat(keyBase64)
        val nonceBytes = decodeBase64Compat(nonceBase64url)
        val combined = decodeBase64Compat(ciphertextBase64url)

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
