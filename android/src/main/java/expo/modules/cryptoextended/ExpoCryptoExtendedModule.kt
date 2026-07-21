package expo.modules.cryptoextended

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.ceil

class ExpoCryptoExtendedModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("ExpoCryptoExtended")

    // Retain native HKDF execution, accepting dynamic salt and info passed from JS
    AsyncFunction("deriveKey") { ikmHex: String, saltHex: String, infoHex: String ->
      val ikm = ikmHex.decodeHex()
      val salt = if (saltHex.isNotEmpty()) saltHex.decodeHex() else ByteArray(32)
      val info = infoHex.decodeHex()

      val derivedKeyBytes = hkdfSha256(ikm, salt, info, 32)
      return@AsyncFunction derivedKeyBytes.toHex()
    }
  }

  // Native HKDF-SHA256 Implementation in Kotlin
  private fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    val saltKey = SecretKeySpec(if (salt.isEmpty()) ByteArray(32) else salt, "HmacSHA256")
    mac.init(saltKey)
    val prk = mac.doFinal(ikm)

    val prkKey = SecretKeySpec(prk, "HmacSHA256")
    val hashLen = 32
    val n = ceil(length.toDouble() / hashLen).toInt()
    var okm = ByteArray(0)
    var previousT = ByteArray(0)

    for (i in 1..n) {
      mac.init(prkKey)
      mac.update(previousT)
      mac.update(info)
      mac.update(i.toByte())
      previousT = mac.doFinal()
      okm += previousT
    }

    return okm.copyOf(length)
  }

  // Extension helpers for Hex string conversions
  private fun String.decodeHex(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
  }

  private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}