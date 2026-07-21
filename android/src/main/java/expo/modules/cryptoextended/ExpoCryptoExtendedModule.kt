package expo.modules.cryptoextended

import android.content.Context
import android.content.pm.PackageManager
import android.util.Base64
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.ceil

class ExpoCryptoExtendedModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("ExpoCryptoExtended")

    // 1. Read custom HKDF fallback metadata injected into the AndroidManifest by your config plugin
    val context = appContext.reactContext
    val ai = context?.packageManager?.getApplicationInfo(context.packageName, PackageManager.GET_META_DATA)
    val bundle = ai?.metaData

    val manifestSalt = bundle?.getString("EXPO_CRYPTO_EXTENDED_SALT") ?: "karr-e2e-v1-salt"
    val manifestInfo = bundle?.getString("EXPO_CRYPTO_EXTENDED_INFO") ?: "karr-e2e-v1-aes-gcm-key"

    // 2. Expose these fallback configurations to the TypeScript bridge
    Constants(
      "FALLBACK_SALT" to manifestSalt,
      "FALLBACK_INFO" to manifestInfo
    )

    // 3. Real HKDF-SHA256 Implementation
    Function("hkdfSha256") { ikmBase64: String, salt: String, info: String, keyLength: Int ->
      val ikm = Base64.decode(ikmBase64, Base64.DEFAULT)
      val saltBytes = salt.toByteArray(Charsets.UTF_8)
      val infoBytes = info.toByteArray(Charsets.UTF_8)

      // Step 3a: HKDF-Extract
      val macExtract = Mac.getInstance("HmacSHA256")
      val prkSpec = SecretKeySpec(if (saltBytes.isEmpty()) ByteArray(32) else saltBytes, "HmacSHA256")
      macExtract.init(prkSpec)
      val prk = macExtract.doFinal(ikm)

      // Step 3b: HKDF-Expand
      val macExpand = Mac.getInstance("HmacSHA256")
      macExpand.init(SecretKeySpec(prk, "HmacSHA256"))

      val hashLen = 32
      val iterations = ceil(keyLength.toDouble() / hashLen).toInt()
      val okm = ByteArray(iterations * hashLen)
      var t = ByteArray(0)

      for (i in 1..iterations) {
        macExpand.reset()
        macExpand.update(t)
        macExpand.update(infoBytes)
        macExpand.update(i.toByte())
        t = macExpand.doFinal()
        System.arraycopy(t, 0, okm, (i - 1) * hashLen, t.size)
      }

      // Slice to required output key length and return as Base64
      val resultBytes = okm.copyOfRange(0, keyLength)
      Base64.encodeToString(resultBytes, Base64.NO_WRAP)
    }

    // Placeholders for remaining crypto systems if implemented via JSI or alternative files
    Function("generateKeyPair") { "" }
    Function("computeSharedSecret") { _: String, _: String -> "" }
    Function("aesGcmDecrypt") { _: String, _: String, _: String -> "" }
  }
}